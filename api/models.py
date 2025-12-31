# models.py
from django.db import models
from django.core.validators import MinLengthValidator
import uuid


class RockYouHash(models.Model):
    """Store hashed passwords from RockYou list with multiple hash types"""
    HASH_TYPES = [
        ('md5', 'MD5'),
        ('sha1', 'SHA-1'),
        ('sha256', 'SHA-256'),
        ('sha512', 'SHA-512'),
        ('bcrypt', 'BCrypt'),
        ('ntlm', 'NTLM'),
        ('mysql323', 'MySQL 3.2.3'),
        ('mysql41', 'MySQL 4.1'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hash_value = models.CharField(max_length=512, db_index=True, unique=True)
    hash_type = models.CharField(max_length=20, choices=HASH_TYPES)
    original_password = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['hash_value', 'hash_type']),
            models.Index(fields=['hash_type']),
        ]
        verbose_name_plural = "RockYou Hashes"


class PasswordCheckHistory(models.Model):
    """Audit log for password checks"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    password_hash = models.CharField(max_length=512, blank=True, null=True)
    password_preview = models.CharField(max_length=10, blank=True, null=True)
    is_in_rockyou = models.BooleanField()
    hash_type_checked = models.CharField(max_length=20, blank=True, null=True)
    strength_score = models.IntegerField(default=0)
    client_ip = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['created_at']),
            models.Index(fields=['is_in_rockyou']),
        ]


class GeneratedPassword(models.Model):
    """Store generated passwords for reference"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    password = models.CharField(max_length=255)
    length = models.IntegerField()
    has_special = models.BooleanField(default=False)
    has_numbers = models.BooleanField(default=False)
    has_uppercase = models.BooleanField(default=False)
    is_passphrase = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)