# serializers.py
from rest_framework import serializers
from .models import RockYouHash, PasswordCheckHistory, GeneratedPassword
import re


class PasswordCheckSerializer(serializers.Serializer):
    password = serializers.CharField(required=False, allow_blank=True)
    password_hash = serializers.CharField(required=False, allow_blank=True)
    hash_type = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        if not data.get('password') and not data.get('password_hash'):
            raise serializers.ValidationError(
                "Either 'password' or 'password_hash' must be provided"
            )
        return data


class PasswordStrengthSerializer(serializers.Serializer):
    score = serializers.IntegerField()
    strength = serializers.CharField()
    is_in_rockyou = serializers.BooleanField()
    length = serializers.IntegerField()
    has_uppercase = serializers.BooleanField()
    has_lowercase = serializers.BooleanField()
    has_numbers = serializers.BooleanField()
    has_special = serializers.BooleanField()
    entropy = serializers.FloatField()
    crack_time = serializers.CharField()
    suggestions = serializers.ListField(child=serializers.CharField())


class AddToRockYouSerializer(serializers.Serializer):
    password = serializers.CharField(required=False, allow_blank=True)
    password_hash = serializers.CharField(required=False, allow_blank=True)
    hash_type = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        if not data.get('password') and not data.get('password_hash'):
            raise serializers.ValidationError(
                "Either 'password' or 'password_hash' must be provided"
            )
        if data.get('password_hash') and not data.get('hash_type'):
            raise serializers.ValidationError(
                "hash_type must be specified when providing password_hash"
            )
        return data


class GeneratePasswordSerializer(serializers.Serializer):
    length = serializers.IntegerField(default=12, min_value=8, max_value=64)
    use_passphrase = serializers.BooleanField(default=False)
    use_special = serializers.BooleanField(default=True)
    use_numbers = serializers.BooleanField(default=True)
    use_uppercase = serializers.BooleanField(default=True)
    exclude_similar = serializers.BooleanField(default=True)
    exclude_ambiguous = serializers.BooleanField(default=False)