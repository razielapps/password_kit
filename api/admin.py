# admin.py
from django.contrib import admin
from .models import RockYouHash, PasswordCheckHistory, GeneratedPassword

@admin.register(RockYouHash)
class RockYouHashAdmin(admin.ModelAdmin):
    list_display = ('hash_type', 'hash_value_preview', 'original_password_preview', 'created_at')
    list_filter = ('hash_type', 'created_at')
    search_fields = ('hash_value', 'original_password')
    readonly_fields = ('created_at',)
    
    def hash_value_preview(self, obj):
        return obj.hash_value[:20] + '...' if len(obj.hash_value) > 20 else obj.hash_value
    
    def original_password_preview(self, obj):
        return obj.original_password[:20] + '...' if obj.original_password and len(obj.original_password) > 20 else obj.original_password
    
    hash_value_preview.short_description = 'Hash'
    original_password_preview.short_description = 'Original Password'

@admin.register(PasswordCheckHistory)
class PasswordCheckHistoryAdmin(admin.ModelAdmin):
    list_display = ('password_preview', 'is_in_rockyou', 'strength_score', 'client_ip', 'created_at')
    list_filter = ('is_in_rockyou', 'created_at', 'hash_type_checked')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

@admin.register(GeneratedPassword)
class GeneratedPasswordAdmin(admin.ModelAdmin):
    list_display = ('password_preview', 'length', 'is_passphrase', 'created_at')
    list_filter = ('is_passphrase', 'created_at', 'has_special', 'has_numbers')
    readonly_fields = ('created_at',)
    
    def password_preview(self, obj):
        return obj.password[:10] + '...' if len(obj.password) > 10 else obj.password
    
    password_preview.short_description = 'Password'