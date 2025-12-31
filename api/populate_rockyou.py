# manage.py command or standalone script
import os
import sys
import django
import hashlib
import bcrypt
import requests
from pathlib import Path

# Add the project to the path
sys.path.append(str(Path(__file__).resolve().parent.parent))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'your_project.settings')
django.setup()

from password_security.models import RockYouHash
from django.db import transaction, connection
from django.core.management.base import BaseCommand
import logging
import gzip
from io import StringIO

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Populate RockYou database from file or download'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--file',
            type=str,
            help='Path to RockYou.txt file'
        )
        parser.add_argument(
            '--url',
            type=str,
            default='https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt',
            help='URL to download RockYou.txt'
        )
        parser.add_argument(
            '--limit',
            type=int,
            default=100000,
            help='Limit number of passwords to process'
        )
        parser.add_argument(
            '--hash-types',
            type=str,
            default='md5,sha1,sha256',
            help='Comma-separated list of hash types to generate'
        )
    
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting RockYou database population...'))
        
        file_path = options['file']
        url = options['url']
        limit = options['limit']
        hash_types = options['hash_types'].split(',')
        
        # Get passwords
        passwords = self._get_passwords(file_path, url, limit)
        
        # Process in batches
        batch_size = 1000
        total_processed = 0
        total_added = 0
        
        for i in range(0, len(passwords), batch_size):
            batch = passwords[i:i + batch_size]
            added = self._process_batch(batch, hash_types)
            
            total_processed += len(batch)
            total_added += added
            
            self.stdout.write(
                f'Processed: {total_processed}/{len(passwords)}, '
                f'Added: {total_added} hashes'
            )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Population complete! Processed {total_processed} passwords, '
                f'added {total_added} hash entries.'
            )
        )
    
    def _get_passwords(self, file_path, url, limit):
        """Get passwords from file or download"""
        passwords = []
        
        if file_path and os.path.exists(file_path):
            self.stdout.write(f'Reading from file: {file_path}')
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    password = line.strip()
                    if password and len(password) <= 100:
                        passwords.append(password)
        
        else:
            self.stdout.write(f'Downloading from: {url}')
            try:
                response = requests.get(url, stream=True, timeout=30)
                response.raise_for_status()
                
                # Check if it's gzipped
                if url.endswith('.gz'):
                    import gzip
                    content = gzip.decompress(response.content)
                    lines = content.decode('utf-8', errors='ignore').split('\n')
                else:
                    lines = response.iter_lines(decode_unicode=True)
                
                for i, line in enumerate(lines):
                    if i >= limit:
                        break
                    password = line.strip()
                    if password and len(password) <= 100:
                        passwords.append(password)
                        
                    if i % 10000 == 0:
                        self.stdout.write(f'Downloaded {i} passwords...')
            
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Failed to download: {str(e)}')
                )
                # Fallback to sample passwords
                passwords = self._get_sample_passwords(limit)
        
        return passwords[:limit]
    
    def _get_sample_passwords(self, limit):
        """Get sample passwords for testing"""
        common_passwords = [
            'password', '123456', '12345678', '1234', 'qwerty', '12345',
            'dragon', 'baseball', 'football', 'letmein', 'monkey', 'abc123',
            'mustang', 'michael', 'shadow', 'master', 'jennifer', '111111',
            'superman', 'harley', 'freedom', 'matrix', 'hello', 'secret',
            'admin', 'welcome', 'password1', 'sunshine', 'iloveyou',
            'trustno1', 'admin123', 'passw0rd', 'ninja', 'azerty'
        ]
        
        # Generate some variations
        sample_passwords = []
        for base in common_passwords:
            for i in range(10):
                sample_passwords.append(f"{base}{i}")
        
        return sample_passwords[:limit]
    
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
            salt = bcrypt.gensalt(rounds=4)  # Lower rounds for faster population
            return bcrypt.hashpw(password_bytes, salt).decode('utf-8')
        elif hash_type == 'ntlm':
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    @transaction.atomic
    def _process_batch(self, batch, hash_types):
        """Process a batch of passwords"""
        added_count = 0
        hash_entries = []
        
        for password in batch:
            for hash_type in hash_types:
                try:
                    hash_value = self._hash_password(password, hash_type)
                    
                    hash_entries.append(RockYouHash(
                        hash_value=hash_value,
                        hash_type=hash_type,
                        original_password=password[:100]
                    ))
                    
                except Exception as e:
                    logger.debug(f"Failed to hash {password} with {hash_type}: {str(e)}")
                    continue
        
        # Bulk create
        if hash_entries:
            RockYouHash.objects.bulk_create(
                hash_entries,
                ignore_conflicts=True,
                batch_size=1000
            )
            added_count = len(hash_entries)
        
        return added_count


# For standalone execution
if __name__ == '__main__':
    # Create a sample population script
    print("Creating sample RockYou database...")
    
    # Sample passwords to populate
    sample_passwords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', 'letmein', 'dragon', 'baseball', 'football',
        'hello', 'secret', 'admin', 'welcome', 'passw0rd'
    ]
    
    from django.db import transaction
    
    with transaction.atomic():
        for password in sample_passwords:
            for hash_type in ['md5', 'sha1', 'sha256']:
                try:
                    hash_value = hashlib.md5(password.encode()).hexdigest() if hash_type == 'md5' else \
                                hashlib.sha1(password.encode()).hexdigest() if hash_type == 'sha1' else \
                                hashlib.sha256(password.encode()).hexdigest()
                    
                    RockYouHash.objects.get_or_create(
                        hash_value=hash_value,
                        hash_type=hash_type,
                        defaults={'original_password': password}
                    )
                except:
                    continue
    
    print(f"Created {RockYouHash.objects.count()} hash entries")