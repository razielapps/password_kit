# PasswordKit
## Password Security API

A Django REST API for password security analysis, RockYou database checking, and secure password generation.

## Features

- ✅ **Password Security Check**: Verify if passwords are in the RockYou compromised password list
- ✅ **Multiple Hash Support**: MD5, SHA-1, SHA-256, SHA-512, BCrypt, NTLM, MySQL hashes
- ✅ **Password Strength Analysis**: Comprehensive strength scoring with suggestions
- ✅ **Secure Password Generation**: Generate strong passwords or passphrases
- ✅ **Audit Logging**: Track all password checks for security auditing
- ✅ **Admin Interface**: Django admin for managing the database
- ✅ **Health Checks**: System monitoring endpoints
- ✅ **Caching**: Performance-optimized with caching

## Quick Start

### 1. Installation

```bash
# Clone and install dependencies
git clone <your-repo>
cd password-security-api
pip install -r requirements.txt

# Configure database
python manage.py migrate
```

### 2. Populate RockYou Database

```bash
# Populate with sample passwords (for testing)
python manage.py populate_rockyou --limit 1000

# Or download full RockYou list
python manage.py populate_rockyou --limit 100000
```

### 3. Run the Server

```bash
# Development
python manage.py runserver

# Production (with Gunicorn)
gunicorn your_project.wsgi:application --workers 4
```

## API Endpoints

### Health Check
```bash
GET /api/health/
```
Returns system status and database connection info.

### Check Password
```bash
POST /api/rockyou/
Content-Type: application/json

{
  "password": "yourpassword123"
}
```

**Response:**
```json
{
  "is_in_rockyou": false,
  "strength_analysis": {
    "score": 85,
    "strength": "Very Strong",
    "length": 16,
    "has_uppercase": true,
    "has_lowercase": true,
    "has_numbers": true,
    "has_special": true,
    "entropy": 95.6,
    "crack_time": "Centuries",
    "suggestions": []
  },
  "recommendation": "Consider using"
}
```

### Check Hash
```bash
GET /api/rockyou/?password_hash=5f4dcc3b5aa765d61d8327deb882cf99&hash_type=md5
```

### Generate Password
```bash
GET /api/password/generate/?length=16&use_special=true&use_passphrase=false
```

**Parameters:**
- `length`: Password length (8-64, default: 12)
- `use_passphrase`: Generate passphrase (default: false)
- `use_special`: Include special characters (default: true)
- `use_numbers`: Include numbers (default: true)
- `use_uppercase`: Include uppercase (default: true)

### Add to RockYou Database
```bash
PUT /api/rockyou/
Content-Type: application/json

{
  "password": "weakpassword"
}
```

## Database Schema

### RockYouHash
- `hash_value`: The hashed password
- `hash_type`: Hash algorithm used
- `original_password`: Original password (truncated)
- `created_at`: Timestamp

### PasswordCheckHistory
- Audit log of all password checks
- Includes client IP, user agent, and results

### GeneratedPassword
- Store generated passwords for reference

## Admin Interface

Access the Django admin at `/admin/` to:
- View/search all RockYou hashes
- Monitor password check history
- Manage generated passwords
- Export data

## Configuration

### Environment Variables
```bash
# Database
export DATABASE_URL=postgresql://user:pass@localhost/dbname

# Security
export SECRET_KEY=your-secret-key
export DEBUG=False  # Set to False in production

# Rate Limiting (optional)
export RATE_LIMIT_PER_MINUTE=100
```

### Settings
Configure in `settings.py`:
```python
# Cache configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}

# Security settings
SECURE_SSL_REDIRECT = True  # In production
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Never store plaintext passwords** - Only hashes are stored
2. **Use HTTPS in production** - All endpoints should be encrypted
3. **Implement rate limiting** - Prevent brute force attacks
4. **Regularly update RockYou DB** - New compromised passwords emerge daily
5. **Audit logs** - Keep for compliance and security monitoring
6. **API Keys** - Consider adding authentication for write operations

## Development

### Running Tests
```bash
python manage.py test password_security
```

### Adding New Hash Types
1. Add to `HASH_TYPES` in `models.py`
2. Implement hash function in `views.py:_hash_password()`
3. Update serializers and validation

### Extending Features
The system is modular and can be extended with:
- Additional password policies
- Integration with external breach databases
- Custom password generation rules
- User-specific password histories

## Deployment

### Docker Deployment
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "your_project.wsgi:application", "--bind", "0.0.0.0:8000"]
```

### Production Checklist
- [ ] Set `DEBUG=False`
- [ ] Configure proper database (PostgreSQL recommended)
- [ ] Set up Redis for caching
- [ ] Configure HTTPS with valid certificates
- [ ] Set up monitoring/alerting
- [ ] Implement backup strategy
- [ ] Configure firewall rules
- [ ] Set up log aggregation

## API Rate Limits

**Current Implementation:** No built-in rate limiting (add based on needs)

**Recommended Limits:**
- Read operations: 100 requests/minute
- Write operations: 10 requests/minute
- Password generation: 50 requests/minute

## Troubleshooting

### Common Issues

1. **"Database not populated"**
   ```bash
   python manage.py populate_rockyou --limit 1000
   ```

2. **"Hash type not supported"**
   - Check `RockYouHash.HASH_TYPES` for supported algorithms
   - Ensure hash_type parameter matches exactly

3. **Performance issues**
   - Enable caching with Redis
   - Add database indexes on frequently queried fields
   - Use pagination for large result sets

### Logs
Check application logs in:
- Django logs (`settings.LOGGING`)
- Server logs (Gunicorn/uWSGI)
- Database query logs

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Submit pull request

## License

MIT License - See LICENSE file for details.

## Support

For issues and feature requests:
1. Check existing issues
2. Create new issue with detailed description
3. Include steps to reproduce

---

**Note:** This is a security-critical application. Always review code changes, especially in hash functions and password handling logic. Regular security audits are recommended.

---
## Author
---
Ekhomwandolor Conscience (AVT CONSCIENCE)
avtxconscience@gmail.com

---
# INFO

# this api was boostraped by [tab_drf](https://github.com/razielapps/tap_drf)