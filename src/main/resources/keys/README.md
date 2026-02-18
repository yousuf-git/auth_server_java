# RSA Key Pair for JWT Signing

## ⚠️ SECURITY WARNING

This directory contains RSA key pairs used for JWT token signing.

### Files

- `private_key_pkcs8.pem` - **PRIVATE KEY** - Used to sign JWT tokens
- `public_key.pem` - **PUBLIC KEY** - Used to verify JWT tokens
- `private_key.pem` - Original private key (not used directly)

### Security Guidelines

#### 🔒 Private Key (`private_key_pkcs8.pem`)

**CRITICAL - KEEP SECURE:**

- ✅ **DO:**
  - Keep this file secure and never expose it
  - Use secure vaults in production (AWS Secrets Manager, Azure Key Vault, etc.)
  - Add to `.gitignore` to prevent accidental commits
  - Rotate keys periodically (recommended: every 90 days)
  - Set proper file permissions: `chmod 600 private_key_pkcs8.pem`

- ❌ **DON'T:**
  - Never commit to version control (Git, SVN, etc.)
  - Never share via email, chat, or unsecured channels
  - Never expose through public APIs
  - Never log or print in application logs

#### 🌐 Public Key (`public_key.pem`)

**CAN BE SHARED:**

- ✅ Safe to distribute to external systems
- ✅ Exposed via `/api/public-key` endpoint
- ✅ Can be committed to version control (optional)
- ✅ No security risk if exposed

### Development vs Production

#### Development (Current Setup)

These keys are for **DEVELOPMENT ONLY**. They are:
- Generated locally
- Stored in the project directory
- Used for testing and development

#### Production Setup

**NEVER use these keys in production!**

For production:
1. Generate new key pairs in a secure environment
2. Store private key in a secrets management service:
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault
   - Kubernetes Secrets
3. Set file permissions: `chmod 600 private_key_pkcs8.pem`
4. Use environment variables to reference key paths:
   ```bash
   export RSA_PRIVATE_KEY_PATH=/secure/path/to/private_key_pkcs8.pem
   export RSA_PUBLIC_KEY_PATH=/secure/path/to/public_key.pem
   ```

### Key Generation

If you need to regenerate keys:

```bash
# Generate private key (2048-bit RSA)
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Convert private key to PKCS8 format (Java compatibility)
openssl pkcs8 -topk8 -inform PEM -outform PEM \
  -in private_key.pem -out private_key_pkcs8.pem -nocrypt
```

**Important:** After regenerating:
- All existing JWT tokens will become invalid
- External systems must fetch the new public key
- Restart the application

### File Permissions

Set proper permissions on Unix/Linux systems:

```bash
# Private keys - only owner can read/write
chmod 600 private_key*.pem

# Public key - everyone can read
chmod 644 public_key.pem
```

### .gitignore Configuration

Add to your `.gitignore`:

```gitignore
# RSA Private Keys - NEVER commit to Git
src/main/resources/keys/private_key*.pem

# Optional: Also ignore public key if you prefer
# src/main/resources/keys/public_key.pem
```

### Key Rotation Strategy

Recommended key rotation schedule:

1. **Generate new key pair** (90 days before expiration)
2. **Support both old and new keys** temporarily
3. **Update public key endpoint** to serve new key
4. **Wait for token expiration** (5 minutes for access tokens)
5. **Remove old key support** after transition period

### Backup

**Backup private keys securely:**

```bash
# Encrypt backup
openssl enc -aes-256-cbc -salt \
  -in private_key_pkcs8.pem \
  -out private_key_backup.pem.enc

# Store encrypted backup in secure location
```

### Key Specifications

- **Algorithm**: RSA
- **Key Size**: 2048 bits
- **Format**: PEM
- **Private Key Format**: PKCS8 (unencrypted)
- **Public Key Format**: X.509 SubjectPublicKeyInfo

### Compliance

These keys are suitable for:
- ✅ OAuth 2.0 / OpenID Connect
- ✅ JWT (JSON Web Tokens) - RS256
- ✅ General RSA encryption/signing
- ⚠️ **Not suitable** for long-term encrypted storage (use AES for that)

### Troubleshooting

#### "Permission Denied" Error

```bash
# Fix file permissions
chmod 600 private_key_pkcs8.pem
chmod 644 public_key.pem
```

#### "Invalid Key Format" Error

Verify key format:
```bash
# Check private key
openssl rsa -in private_key_pkcs8.pem -check -noout

# Check public key
openssl rsa -pubin -in public_key.pem -text -noout
```

#### "Key Not Found" Error

Ensure files are in the correct location:
- Development: `src/main/resources/keys/`
- Production: Path specified in environment variables

---

## Questions?

Refer to:
- [RSA_JWT_QUICK_START.md](../../documentations/RSA_JWT_QUICK_START.md)
- [EXTERNAL_SYSTEM_INTEGRATION.md](../../documentations/EXTERNAL_SYSTEM_INTEGRATION.md)

---

**Last Updated**: February 2026
