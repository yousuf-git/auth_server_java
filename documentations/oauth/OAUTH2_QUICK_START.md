# 🚀 OAuth2 Quick Start Guide

## Prerequisites

Before you start, ensure you have:
- Java 17 or higher installed
- Maven installed
- PostgreSQL database running
- Google Cloud Console access

## Step 1: Google Cloud Console Setup (5 minutes)

### 1.1 Create OAuth2 Credentials

1. **Go to Google Cloud Console**: https://console.cloud.google.com/
2. **Create a new project** (or select existing):
   - Click on project dropdown at the top
   - Click "New Project"
   - Enter name: `spring-security-oauth2`
   - Click "Create"

3. **Enable Google+ API**:
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API"
   - Click "Enable"

4. **Create OAuth2 Credentials**:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth client ID"
   - Choose "Web application"
   - Set name: `Spring Boot OAuth2 Client`
   - Add Authorized JavaScript origins:
     ```
     http://localhost:8080
     ```
   - Add Authorized redirect URIs:
     ```
     http://localhost:8080/login/oauth2/code/google
     ```
   - Click "Create"
   - **Copy Client ID and Client Secret** (you'll need these!)

### 1.2 Configure OAuth Consent Screen

1. Go to "OAuth consent screen"
2. Select "External" (for testing with any Google account)
3. Fill in required fields:
   - App name: `Spring Security OAuth2 Demo`
   - User support email: your email
   - Developer contact: your email
4. Add scopes:
   - `email`
   - `profile`
   - `openid`
5. Add test users (your Google account)
6. Click "Save and Continue"

## Step 2: Configure Application (2 minutes)

### 2.1 Set Environment Variables

**Linux/Mac:**
```bash
export GOOGLE_CLIENT_ID="your-client-id-here"
export GOOGLE_CLIENT_SECRET="your-client-secret-here"
export DB_URL="jdbc:postgresql://localhost:5432/demo"
export DB_USERNAME="postgres"
export DB_PASSWORD="password"
```

**Windows (PowerShell):**
```powershell
$env:GOOGLE_CLIENT_ID="your-client-id-here"
$env:GOOGLE_CLIENT_SECRET="your-client-secret-here"
$env:DB_URL="jdbc:postgresql://localhost:5432/demo"
$env:DB_USERNAME="postgres"
$env:DB_PASSWORD="password"
```

**Windows (CMD):**
```cmd
set GOOGLE_CLIENT_ID=your-client-id-here
set GOOGLE_CLIENT_SECRET=your-client-secret-here
set DB_URL=jdbc:postgresql://localhost:5432/demo
set DB_USERNAME=postgres
set DB_PASSWORD=password
```

### 2.2 Or Edit Configuration File Directly

Open `src/main/resources/application-dev.yml` and replace:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: YOUR_ACTUAL_CLIENT_ID_HERE
            client-secret: YOUR_ACTUAL_CLIENT_SECRET_HERE
```

## Step 3: Database Setup (2 minutes)

### 3.1 Create Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE demo;
```

### 3.2 Add OAuth2 Columns

Run this SQL migration:

```sql
-- Connect to demo database
\c demo;

-- Add OAuth2 columns to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS provider VARCHAR(20),
ADD COLUMN IF NOT EXISTS provider_id VARCHAR(255),
ADD COLUMN IF NOT EXISTS image_url VARCHAR(512),
ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false;

-- Make password nullable for OAuth2 users
ALTER TABLE users 
ALTER COLUMN password DROP NOT NULL;

-- Add index for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_provider ON users(provider, provider_id);
```

Or use the provided SQL file:
```bash
psql -U postgres -d demo -f add_oauth2_columns.sql
```

## Step 4: Build and Run (1 minute)

### 4.1 Build the Application

```bash
# Clean and build
mvn clean package -DskipTests

# Or if you want to run tests
mvn clean package
```

### 4.2 Run the Application

```bash
# Using Maven
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Or using the JAR
java -jar target/Security-0.0.1-SNAPSHOT.jar --spring.profiles.active=dev
```

## Step 5: Test OAuth2 Login (1 minute)

### 5.1 Open the Demo Page

Navigate to: **http://localhost:8080/oauth2-demo.html**

You should see a beautiful login page with:
- "Continue with Google" button
- Instructions
- Information box

### 5.2 Test the OAuth2 Flow

1. **Click "Continue with Google"**
2. **Sign in** with your Google account (must be added as test user)
3. **Grant permissions** for email and profile access
4. **Get redirected** back with JWT token
5. **See your user info** displayed on the page

### 5.3 Verify Token Works

The demo page automatically tests your JWT token by calling:
```
GET /test/user
```

Check browser console (F12) for authentication test results.

## Step 6: Test API Endpoints

### 6.1 Get Current User Info

```bash
# Replace YOUR_TOKEN with the token from the demo page
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/oauth2/user
```

**Expected Response:**
```json
{
  "id": 1,
  "username": "m.yousuf",
  "email": "m.yousuf@gmail.com",
  "roles": ["ROLE_USER"],
  "provider": "GOOGLE"
}
```

### 6.2 Access Protected Endpoint

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/test/user
```

**Expected Response:**
```
User Access content.
```

### 6.3 Check User Details

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     http://localhost:8080/test/userdetails
```

## Architecture Overview

```
┌─────────────┐      1. Click      ┌──────────────┐
│   Browser   │ ──────────────────> │   Demo Page  │
│             │   "Login with      │              │
└─────────────┘      Google"       └──────────────┘
      │                                     │
      │ 2. Redirect to                     │
      │    /oauth2/authorize/google        │
      ▼                                     ▼
┌─────────────────────────────────────────────────┐
│         Spring Security OAuth2 Client            │
├─────────────────────────────────────────────────┤
│  3. Redirect to Google OAuth2                   │
└─────────────────────────────────────────────────┘
      │                                     │
      │ 4. User signs in with Google       │
      ▼                                     ▼
┌─────────────────────────────────────────────────┐
│              Google OAuth2 Server                │
├─────────────────────────────────────────────────┤
│  5. Returns authorization code                  │
└─────────────────────────────────────────────────┘
      │                                     │
      │ 6. Exchange code for token         │
      ▼                                     ▼
┌─────────────────────────────────────────────────┐
│      CustomOAuth2UserService                    │
├─────────────────────────────────────────────────┤
│  7. Fetch user info, create/update DB record    │
└─────────────────────────────────────────────────┘
      │                                     │
      │ 8. Create UserDetailsImpl           │
      ▼                                     ▼
┌─────────────────────────────────────────────────┐
│    OAuth2AuthenticationSuccessHandler           │
├─────────────────────────────────────────────────┤
│  9. Generate JWT token with JwtUtils            │
└─────────────────────────────────────────────────┘
      │                                     │
      │ 10. Redirect with token             │
      ▼                                     ▼
┌─────────────────────────────────────────────────┐
│              Browser receives:                   │
│  /oauth2-demo.html?token=xxx&userId=1&...      │
└─────────────────────────────────────────────────┘
```

## Troubleshooting

### Issue: "Error 401: Invalid Client"

**Solution:**
- Check that Client ID and Client Secret are correct
- Verify redirect URI in Google Console matches: `http://localhost:8080/login/oauth2/code/google`
- Ensure Google+ API is enabled

### Issue: "Error 403: Access Denied"

**Solution:**
- Add your Google account as a test user in OAuth consent screen
- Check that scopes (email, profile) are configured
- Verify app is in "Testing" mode if using external user type

### Issue: Application fails to start

**Solution:**
- Check environment variables are set correctly
- Verify PostgreSQL is running: `pg_isready`
- Check database credentials in `application-dev.yml`
- Ensure port 8080 is not in use: `lsof -i :8080` (Linux/Mac) or `netstat -ano | findstr :8080` (Windows)

### Issue: "No such column: provider"

**Solution:**
- Run the database migration script from Step 3.2
- Verify columns exist: `\d users` in psql

### Issue: Token not working in API calls

**Solution:**
- Check token format: should be `Bearer <token>`
- Verify token hasn't expired (check JWT expiration time)
- Ensure JWT secret key is configured in `application-dev.yml`
- Check browser console for error messages

## What's Next?

✅ **Your OAuth2 integration is ready!**

Now you can:

1. **Customize the redirect page**: Edit `oauth2-demo.html` for your needs
2. **Add more OAuth2 providers**: Facebook, GitHub, etc.
3. **Implement refresh tokens**: For long-lived sessions
4. **Add role-based authorization**: Assign roles to OAuth2 users
5. **Deploy to production**: Update redirect URIs for your domain

## Security Best Practices

- ✅ Never commit Client ID/Secret to version control (use environment variables)
- ✅ Use HTTPS in production (update redirect URIs to https://)
- ✅ Implement CSRF protection for state parameter
- ✅ Add rate limiting to prevent abuse
- ✅ Validate redirect URIs to prevent open redirects
- ✅ Store OAuth2 access tokens securely if needed
- ✅ Implement token refresh mechanism for long sessions
- ✅ Add logging for security events (failed logins, etc.)

## Support

For detailed documentation, see:
- `OAUTH2_SETUP.md` - Comprehensive OAuth2 documentation
- `TEST_DOCUMENTATION.md` - Testing guide
- `readme.md` - General project documentation

## Time Summary

- **Google Cloud Console Setup**: 5 minutes
- **Application Configuration**: 2 minutes
- **Database Setup**: 2 minutes
- **Build and Run**: 1 minute
- **Testing**: 1 minute

**Total Time: ~11 minutes** ⏱️

---

### Keep Programming !!!