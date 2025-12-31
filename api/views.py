# views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from django.views.decorators.vary import vary_on_cookie
from django.db import transaction
from django.db.models import Q
import hashlib
import bcrypt
import secrets
import string
import math
import re
import logging
from .models import RockYouHash, PasswordCheckHistory, GeneratedPassword
from .serializers import (
    PasswordCheckSerializer, 
    PasswordStrengthSerializer,
    AddToRockYouSerializer,
    GeneratePasswordSerializer
)

logger = logging.getLogger(__name__)


class HealthView(APIView):
    permission_classes = [AllowAny]
    
    @method_decorator(cache_page(60))
    def get(self, request):
        """Health check endpoint with caching"""
        try:
            # Check database connection
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            
            # Check cache
            cache.set('health_check', 'ok', 5)
            cache_status = cache.get('health_check') == 'ok'
            
            # Count some metrics
            rockyou_count = RockYouHash.objects.count()
            
            return Response({
                "status": "healthy",
                "database": "connected",
                "cache": "working" if cache_status else "error",
                "rockyou_entries": rockyou_count,
                "timestamp": timezone.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return Response(
                {"status": "unhealthy", "error": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )


class RockYouView(APIView):
    permission_classes = [AllowAny]
    
    def _get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def _hash_password(self, password, hash_type):
        """Hash password using specified algorithm"""
        password_bytes = password.encode('utf-8')
        
        if hash_type == 'md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif hash_type == 'sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif hash_type == 'sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif hash_type == 'sha512':
            return hashlib.sha512(password_bytes).hexdigest()
        elif hash_type == 'bcrypt':
            # Generate salt and hash
            salt = bcrypt.gensalt()
            return bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        elif hash_type == 'ntlm':
            # NTLM hash
            import hashlib
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        elif hash_type == 'mysql323':
            # MySQL 3.2.3 hash
            nr = 1345345333
            add = 7
            nr2 = 0x12345671
            
            for c in password:
                if c == ' ' or c == '\t':
                    continue
                nr ^= (((nr & 63) + add) * ord(c)) + (nr << 8)
                nr2 += (nr2 << 8) ^ nr
                add += ord(c)
            
            result1 = nr & ((1 << 31) - 1)
            result2 = nr2 & ((1 << 31) - 1)
            return f"{result1:08x}{result2:08x}"
        elif hash_type == 'mysql41':
            # MySQL 4.1+ hash (SHA1 of SHA1)
            stage1 = hashlib.sha1(password_bytes).digest()
            return hashlib.sha1(stage1).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def _check_password_strength(self, password):
        """Calculate password strength score (0-100)"""
        score = 0
        suggestions = []
        
        # Length check
        length = len(password)
        if length >= 8:
            score += 10
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        if length < 8:
            suggestions.append("Password should be at least 8 characters long")
        
        # Character variety
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        if has_upper:
            score += 10
        if has_lower:
            score += 10
        if has_digit:
            score += 10
        if has_special:
            score += 10
        
        if not has_upper:
            suggestions.append("Add uppercase letters")
        if not has_lower:
            suggestions.append("Add lowercase letters")
        if not has_digit:
            suggestions.append("Add numbers")
        if not has_special:
            suggestions.append("Add special characters")
        
        # Entropy calculation
        pool_size = 0
        if has_upper:
            pool_size += 26
        if has_lower:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_special:
            pool_size += 32
        
        if pool_size > 0:
            entropy = length * math.log2(pool_size)
            score += min(entropy / 2, 30)  # Max 30 points for entropy
        
        # Common patterns
        common_patterns = [
            '123456', 'password', 'qwerty', 'admin', 'welcome',
            'monkey', 'dragon', 'baseball', 'football', 'letmein'
        ]
        
        for pattern in common_patterns:
            if pattern in password.lower():
                score -= 20
                suggestions.append("Avoid common words and patterns")
                break
        
        # Sequential characters
        if re.search(r'(.)\1{2,}', password):
            score -= 10
            suggestions.append("Avoid repeated characters")
        
        # Final score clamping
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        # Estimate crack time
        if entropy > 0:
            guesses_per_second = 1e9  # 1 billion guesses/second
            seconds_to_crack = (pool_size ** length) / guesses_per_second
            
            if seconds_to_crack < 60:
                crack_time = "Instantly"
            elif seconds_to_crack < 3600:
                crack_time = f"{int(seconds_to_crack/60)} minutes"
            elif seconds_to_crack < 86400:
                crack_time = f"{int(seconds_to_crack/3600)} hours"
            elif seconds_to_crack < 31536000:
                crack_time = f"{int(seconds_to_crack/86400)} days"
            else:
                crack_time = f"{int(seconds_to_crack/31536000)} years"
        else:
            crack_time = "Instantly"
        
        return {
            "score": int(score),
            "strength": strength,
            "length": length,
            "has_uppercase": has_upper,
            "has_lowercase": has_lower,
            "has_numbers": has_digit,
            "has_special": has_special,
            "entropy": round(entropy, 2) if 'entropy' in locals() else 0,
            "crack_time": crack_time,
            "suggestions": suggestions[:3]  # Limit to top 3 suggestions
        }
    
    def post(self, request):
        """
        Check if password is in RockYou list and analyze strength
        Query params: password, hash_type (optional)
        """
        serializer = PasswordCheckSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid input", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        password = serializer.validated_data.get('password')
        hash_type = serializer.validated_data.get('hash_type', '')
        
        if not password:
            return Response(
                {"error": "Password is required for POST method"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if password is in RockYou list
        is_in_rockyou = False
        hash_types_to_check = []
        
        if hash_type:
            hash_types_to_check = [hash_type]
        else:
            # Check all common hash types
            hash_types_to_check = ['md5', 'sha1', 'sha256', 'ntlm']
        
        for h_type in hash_types_to_check:
            try:
                password_hash = self._hash_password(password, h_type)
                exists = RockYouHash.objects.filter(
                    hash_value=password_hash,
                    hash_type=h_type
                ).exists()
                
                if exists:
                    is_in_rockyou = True
                    break
            except ValueError:
                continue
        
        # Calculate password strength
        strength_analysis = self._check_password_strength(password)
        
        # Log the check for audit
        try:
            PasswordCheckHistory.objects.create(
                password_preview=password[:3] + '***' if len(password) > 3 else '***',
                is_in_rockyou=is_in_rockyou,
                strength_score=strength_analysis['score'],
                client_ip=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
        except Exception as e:
            logger.error(f"Failed to log password check: {str(e)}")
        
        response_data = {
            "is_in_rockyou": is_in_rockyou,
            "strength_analysis": strength_analysis,
            "recommendation": "DO NOT USE" if is_in_rockyou else "Consider using" if strength_analysis['score'] > 60 else "Do not use"
        }
        
        return Response(response_data)
    
    def get(self, request):
        """
        Check if password hash is in RockYou list
        Query params: password_hash, hash_type (required)
        """
        password_hash = request.query_params.get("password_hash", "")
        hash_type = request.query_params.get("hash_type", "")
        
        if not password_hash or not hash_type:
            return Response(
                {"error": "Both password_hash and hash_type parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate hash type
        valid_hash_types = dict(RockYouHash.HASH_TYPES).keys()
        if hash_type not in valid_hash_types:
            return Response(
                {"error": f"Invalid hash type. Valid types: {', '.join(valid_hash_types)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if hash exists
        exists = RockYouHash.objects.filter(
            hash_value=password_hash,
            hash_type=hash_type
        ).exists()
        
        # Log the check
        try:
            PasswordCheckHistory.objects.create(
                password_hash=password_hash[:50],
                is_in_rockyou=exists,
                hash_type_checked=hash_type,
                client_ip=self._get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:255]
            )
        except Exception as e:
            logger.error(f"Failed to log hash check: {str(e)}")
        
        return Response({
            "hash_found": exists,
            "message": "Hash found in RockYou database" if exists else "Hash not found in RockYou database",
            "hash_type": hash_type
        })
    
    @transaction.atomic
    def put(self, request):
        """
        Add password or hash to RockYou list
        """
        serializer = AddToRockYouSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid input", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        password = serializer.validated_data.get('password')
        password_hash = serializer.validated_data.get('password_hash')
        hash_type = serializer.validated_data.get('hash_type', '')
        
        added_hashes = []
        
        if password:
            # Hash with multiple algorithms and store each
            hash_types = ['md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'mysql41']
            
            for h_type in hash_types:
                try:
                    hashed = self._hash_password(password, h_type)
                    
                    # Check if already exists
                    if not RockYouHash.objects.filter(
                        hash_value=hashed,
                        hash_type=h_type
                    ).exists():
                        
                        RockYouHash.objects.create(
                            hash_value=hashed,
                            hash_type=h_type,
                            original_password=password[:100]  # Store truncated original
                        )
                        added_hashes.append(h_type)
                        
                except ValueError as e:
                    logger.warning(f"Failed to hash with {h_type}: {str(e)}")
                    continue
        
        elif password_hash and hash_type:
            # Store the provided hash
            if not RockYouHash.objects.filter(
                hash_value=password_hash,
                hash_type=hash_type
            ).exists():
                
                RockYouHash.objects.create(
                    hash_value=password_hash,
                    hash_type=hash_type
                )
                added_hashes.append(hash_type)
        
        return Response({
            "success": True,
            "added_hashes": added_hashes,
            "message": f"Added {len(added_hashes)} hash(es) to RockYou database"
        })


class PasswordGeneratorView(APIView):
    permission_classes = [AllowAny]
    
    # Word list for passphrases
    WORD_LIST = [
        'apple', 'brave', 'cloud', 'dragon', 'eagle', 'forest', 'garden', 
        'hammer', 'island', 'jungle', 'knight', 'light', 'mountain', 
        'night', 'ocean', 'planet', 'quiet', 'river', 'silver', 'tiger',
        'unique', 'violet', 'water', 'yellow', 'zebra'
    ]
    
    @method_decorator(cache_page(30))
    def get(self, request):
        """
        Generate a strong password
        Query params: 
        - length: int (default: 12)
        - use_passphrase: bool (default: False)
        - use_special: bool (default: True)
        - use_numbers: bool (default: True)
        - use_uppercase: bool (default: True)
        - exclude_similar: bool (default: True)
        - exclude_ambiguous: bool (default: False)
        """
        serializer = GeneratePasswordSerializer(data=request.query_params)
        if not serializer.is_valid():
            return Response(
                {"error": "Invalid parameters", "details": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        params = serializer.validated_data
        
        if params['use_passphrase']:
            password = self._generate_passphrase(params)
        else:
            password = self._generate_password(params)
        
        # Check if generated password is in RockYou (should be very unlikely)
        is_in_rockyou = False
        for hash_type in ['md5', 'sha1']:
            try:
                password_hash = self._hash_password(password, hash_type)
                exists = RockYouHash.objects.filter(
                    hash_value=password_hash,
                    hash_type=hash_type
                ).exists()
                
                if exists:
                    is_in_rockyou = True
                    break
            except:
                continue
        
        # If password is in RockYou (unlikely but possible), regenerate
        if is_in_rockyou:
            logger.warning(f"Generated password was found in RockYou, regenerating")
            password = self._generate_password(params) if not params['use_passphrase'] else self._generate_passphrase(params)
        
        # Store generated password for reference
        try:
            GeneratedPassword.objects.create(
                password=password,
                length=len(password),
                has_special=params['use_special'],
                has_numbers=params['use_numbers'],
                has_uppercase=params['use_uppercase'],
                is_passphrase=params['use_passphrase']
            )
        except Exception as e:
            logger.error(f"Failed to store generated password: {str(e)}")
        
        # Calculate strength
        from .views import RockYouView
        rockyou_view = RockYouView()
        strength_analysis = rockyou_view._check_password_strength(password)
        
        return Response({
            "password": password,
            "length": len(password),
            "is_passphrase": params['use_passphrase'],
            "strength_analysis": strength_analysis,
            "is_in_rockyou": False  # We already regenerated if it was
        })
    
    def _hash_password(self, password, hash_type):
        """Reuse the hash function from RockYouView"""
        from .views import RockYouView
        rockyou_view = RockYouView()
        return rockyou_view._hash_password(password, hash_type)
    
    def _generate_password(self, params):
        """Generate a random password"""
        length = params['length']
        
        # Character pools
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase if params['use_uppercase'] else ''
        digits = string.digits if params['use_numbers'] else ''
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?' if params['use_special'] else ''
        
        # Exclude similar characters
        if params['exclude_similar']:
            lowercase = lowercase.replace('l', '').replace('o', '')
            uppercase = uppercase.replace('I', '').replace('O', '')
            digits = digits.replace('0', '').replace('1', '')
        
        # Exclude ambiguous characters
        if params['exclude_ambiguous']:
            special = special.replace('<', '').replace('>', '').replace('[', '').replace(']', '').replace('{', '').replace('}', '').replace('(', '').replace(')', '').replace('/', '').replace('\\', '').replace('|', '').replace(';', '').replace(':', '').replace('"', '').replace("'", '').replace('`', '')
        
        # Ensure at least one from each selected category
        all_chars = ''
        password_chars = []
        
        if lowercase:
            password_chars.append(secrets.choice(lowercase))
            all_chars += lowercase
        if uppercase:
            password_chars.append(secrets.choice(uppercase))
            all_chars += uppercase
        if digits:
            password_chars.append(secrets.choice(digits))
            all_chars += digits
        if special:
            password_chars.append(secrets.choice(special))
            all_chars += special
        
        # Fill the rest with random characters
        remaining_length = length - len(password_chars)
        if remaining_length > 0 and all_chars:
            password_chars.extend(secrets.choice(all_chars) for _ in range(remaining_length))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_passphrase(self, params):
        """Generate a memorable passphrase"""
        length = params['length']
        
        # Adjust word count based on desired length
        word_count = max(3, length // 5)
        
        # Select random words
        words = [secrets.choice(self.WORD_LIST) for _ in range(word_count)]
        
        # Apply transformations
        if params['use_uppercase']:
            words = [word.capitalize() for word in words]
        
        if params['use_numbers']:
            # Add a number to one of the words
            index = secrets.randbelow(len(words))
            words[index] = words[index] + str(secrets.randbelow(100))
        
        if params['use_special']:
            # Add a special character
            special_chars = '!@#$%^&*'
            words.append(secrets.choice(special_chars))
        
        # Join with separator
        separators = ['-', '_', '.', ''] if not params['exclude_ambiguous'] else ['-', '_']
        separator = secrets.choice(separators)
        
        passphrase = separator.join(words)
        
        # Trim or pad to desired length
        if len(passphrase) > length:
            passphrase = passphrase[:length]
        elif len(passphrase) < length:
            # Add random characters to reach desired length
            extra_chars = string.ascii_letters + string.digits
            passphrase += ''.join(secrets.choice(extra_chars) for _ in range(length - len(passphrase)))
        
        return passphrase