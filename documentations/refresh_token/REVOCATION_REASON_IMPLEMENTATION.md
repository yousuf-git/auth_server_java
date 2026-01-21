# Revocation Reason Implementation

## Problem Statement

The original refresh token system had a critical design flaw in its theft detection mechanism:

**Scenario:**
1. User has 10 active sessions (max limit reached)
2. User logs in from an 11th device
3. Backend automatically revokes the oldest token due to `MAX_DEVICES_EXCEEDED` policy
4. The 1st device still has the revoked token in its HTTP-only cookie
5. When 1st device tries to refresh, system detects "revoked token reused"
6. System treats this as **token theft** and revokes ALL user sessions
7. **All 11 devices are logged out** - Wrong behavior!

**Root Cause:** The system couldn't differentiate between:
- **Legitimate revocation** (backend removed token due to max sessions)
- **Actual theft** (attacker reusing a stolen, rotated token)

## Solution: RevocationReason Enum

I introduced a `RevocationReason` enum to track **WHY** each token was revoked, enabling smart theft detection.

### RevocationReason Enum Values

```java
public enum RevocationReason {
    /**
     * Token was rotated during normal refresh flow
     * If THIS type of revoked token is reused = THEFT DETECTED
     */
    TOKEN_ROTATION,
    
    /**
     * User explicitly logged out from this session
     * If reused = just deny access gracefully
     */
    MANUAL_LOGOUT,
    
    /**
     * Token was removed due to max session limit
     * If reused = just deny access gracefully (not theft!)
     */
    MAX_DEVICES_EXCEEDED,
    
    /**
     * Revoked because theft was detected
     * (Used when revoking entire token family)
     */
    THEFT_DETECTED,
    
    /**
     * Admin manually revoked the session
     * If reused = just deny access gracefully
     */
    ADMIN_REVOKED
}
```

## Implementation Changes

### 1. Database Schema (`init.sql`)

Added enum type and column to `refresh_tokens` table:

```sql
-- Create enum type
CREATE TYPE REVOCATION_REASON AS ENUM (
    'TOKEN_ROTATION',
    'MANUAL_LOGOUT', 
    'MAX_DEVICES_EXCEEDED',
    'THEFT_DETECTED',
    'ADMIN_REVOKED'
);

-- Add column to refresh_tokens table
ALTER TABLE refresh_token ADD COLUMN revocation_reason REVOCATION_REASON;

-- Add index for query performance
CREATE INDEX idx_refresh_tokens_revocation_reason ON refresh_token(revocation_reason);
```

### 2. RefreshToken Entity

Added field and updated `revoke()` method:

```java
@Enumerated(EnumType.STRING)
@Column(name = "revocation_reason", length = 30)
private RevocationReason revocationReason;

public void revoke(RevocationReason reason) {
    this.revokedAt = Instant.now();
    this.revocationReason = reason;
}

// Backward compatibility - defaults to TOKEN_ROTATION
public void revoke() {
    revoke(RevocationReason.TOKEN_ROTATION);
}
```

### 3. Smart Theft Detection (RefreshTokenService)

**Old Logic** (lines 132-141):
```java
if (currentToken.isRevoked()) {
    // ALWAYS treated as theft - WRONG!
    logger.error("SECURITY ALERT: Revoked token reused!");
    revokeTokenFamily(currentToken.getFamilyId());
    throw new RuntimeException("Token theft detected. All sessions revoked.");
}
```

**New Logic** (Smart Detection):
```java
if (currentToken.isRevoked()) {
    RevocationReason reason = currentToken.getRevocationReason();
    
    // Using the reason to decide action
    switch (reason) {
        case RevocationReason.TOKEN_ROTATION:
            logger.error("SECURITY ALERT: Token theft detected! Rotated token reused. Family: {} User: {}", 
                currentToken.getFamilyId(), currentToken.getUser().getEmail());
            // Revoke entire token family for security
            revokeTokenFamily(currentToken.getFamilyId(), RevocationReason.THEFT_DETECTED);
            throw new RuntimeException("Token theft detected. All sessions revoked. Please login again.");

        case RevocationReason.MAX_DEVICES_EXCEEDED:
            logger.info("Revoked token used due to max devices exceeded. User: {}", currentToken.getUser().getEmail());
            throw new RuntimeException("Session expired due to new login from another device. Please login again.");
        
        case RevocationReason.MANUAL_LOGOUT:
            logger.info("Revoked token used due to manual logout. User: {}", currentToken.getUser().getEmail());
            throw new RuntimeException("Session expired. Please login again.");
        
        case RevocationReason.ADMIN_REVOKED:
            logger.info("Admin Revoked token used. User: {}", currentToken.getUser().getEmail());
            throw new RuntimeException("Session revoked by administrator. Please contact support.");
        
        case RevocationReason.THEFT_DETECTED:
            logger.info("THEFT_DETECTED token reused by User: {}", currentToken.getUser().getEmail());
            throw new RuntimeException("System Marked you as Chiller Chor. Login Again!");

        default:
            logger.info("Revoked token used (reason: {}). User: {}", reason, currentToken.getUser().getEmail());
            throw new RuntimeException("Session expired. Please login again.");
    }
}
```

### 4. Updated Service Methods

All revocation methods now accept a `RevocationReason` parameter:

```java
// RefreshTokenService methods
public void revokeRefreshToken(String rawToken, RevocationReason reason)
public void revokeTokenFamily(String familyId, RevocationReason reason)
public void revokeAllUserTokens(Integer userId, RevocationReason reason)
public void revokeSession(String sessionId, User user) // Uses ADMIN_REVOKED internally
```

**Token Rotation:**
```java
// Old token revoked during rotation
currentToken.revoke(RevocationReason.TOKEN_ROTATION);
```

**Max Sessions Enforcement:**
```java
// Oldest token revoked when limit reached
oldestToken.revoke(RevocationReason.MAX_DEVICES_EXCEEDED);
```

### 5. Updated Repository Queries

Bulk update queries now set both `revokedAt` and `revocationReason`:

```java
@Query("UPDATE RefreshToken rt SET rt.revokedAt = :revokedAt, rt.revocationReason = :reason " +
       "WHERE rt.familyId = :familyId AND rt.revokedAt IS NULL")
int revokeTokenFamily(@Param("familyId") String familyId, 
                      @Param("revokedAt") Instant revokedAt, 
                      @Param("reason") RevocationReason reason);
```

### 6. Controller Updates

**AuthController:**
```java
// Logout - single session
refreshTokenService.revokeRefreshToken(refreshToken, RevocationReason.MANUAL_LOGOUT);

// Logout all sessions
refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.MANUAL_LOGOUT);
```

**SessionController (Admin):**
```java
// Admin revokes user sessions
refreshTokenService.revokeAllUserTokens(userId, RevocationReason.ADMIN_REVOKED);
refreshTokenService.revokeSession(sessionId, user); // Uses ADMIN_REVOKED internally
```

## Behavior Changes

### Scenario 1: Normal Token Rotation (Existing Flow)
1. User refreshes token with valid token
2. Old token revoked with `TOKEN_ROTATION` reason
3. New token issued
4. **If old token reused → THEFT DETECTED → All sessions revoked** ✅

### Scenario 2: Max Sessions Exceeded (FIXED!)
1. User has 10 sessions (max limit)
2. User logs in from 11th device
3. Oldest token revoked with `MAX_DEVICES_EXCEEDED` reason
4. **If 1st device tries to refresh:**
   - System checks: `revocationReason == MAX_DEVICES_EXCEEDED`
   - Just denies access: "Session expired. Please login again."
   - **Does NOT revoke all sessions** ✅

### Scenario 3: Manual Logout
1. User clicks logout
2. Token revoked with `MANUAL_LOGOUT` reason
3. **If user tries to refresh:**
   - System checks: `revocationReason == MANUAL_LOGOUT`
   - Just denies access gracefully
   - **Does NOT trigger theft alert** ✅

### Scenario 4: Admin Revocation
1. Admin revokes user session
2. Token revoked with `ADMIN_REVOKED` reason
3. **If user tries to refresh:**
   - System checks: `revocationReason == ADMIN_REVOKED`
   - Just denies access gracefully
   - **Does NOT trigger theft alert** ✅

## Security Enhancement

This implementation **strengthens security** by:

1. **Accurate Threat Detection:** Only actual theft scenarios (rotated token reuse) trigger family revocation
2. **Reduced False Positives:** Legitimate revocations don't cause unnecessary panic
3. **Better Logging:** Know WHY each token was revoked for audit trails
4. **User Experience:** Users aren't unexpectedly logged out from all devices due to false positives

## Testing Recommendations

### Test Case 1: Max Sessions Limit
1. Login from 10 devices
2. Login from 11th device
3. Try to refresh from 1st device
4. **Expected:** "Session expired" message, other 9 + new session remain active

### Test Case 2: Actual Token Theft
1. Login and capture refresh token
2. Use token once (gets rotated)
3. Try to reuse the old rotated token
4. **Expected:** "Token theft detected" + all sessions revoked

### Test Case 3: Manual Logout
1. Login from device
2. Click logout
3. Try to refresh with old token
4. **Expected:** "Session expired" message, no theft alert

### Test Case 4: Admin Revocation
1. Admin revokes user session
2. User tries to refresh
3. **Expected:** "Session expired" message, no theft alert

## Migration Notes

**Database Migration Required:**
```sql
-- Add enum type (if database is already created)
CREATE TYPE REVOCATION_REASON AS ENUM (
    'TOKEN_ROTATION',
    'MANUAL_LOGOUT', 
    'MAX_DEVICES_EXCEEDED',
    'THEFT_DETECTED',
    'ADMIN_REVOKED'
);

-- Add column to existing table
ALTER TABLE refresh_tokens ADD COLUMN revocation_reason REVOCATION_REASON;

-- Add index for performance
CREATE INDEX idx_refresh_tokens_revocation_reason ON refresh_tokens(revocation_reason);
```

**Existing Revoked Tokens:**
- Existing revoked tokens will have `revocation_reason = NULL`
- System treats NULL as `TOKEN_ROTATION` for safety (default behavior)
- Consider cleaning up old tokens before deploying

## Files Modified

### New Files
- `src/main/java/com/learning/security/enums/RevocationReason.java`

### Modified Files
- `init.sql` - Added enum type and column
- `src/main/java/com/learning/security/models/RefreshToken.java` - Added field and updated methods
- `src/main/java/com/learning/security/services/RefreshTokenService.java` - Smart theft detection
- `src/main/java/com/learning/security/repos/RefreshTokenRepository.java` - Updated queries
- `src/main/java/com/learning/security/controllers/AuthController.java` - Pass revocation reasons
- `src/main/java/com/learning/security/controllers/SessionController.java` - Pass revocation reasons

## Summary

This implementation fixes the critical flaw where legitimate backend revocations (max sessions) were falsely triggering theft detection. Now the system can differentiate between actual security threats (rotated token reuse) and legitimate operational revocations (max devices, logout, admin actions), providing both better security and improved user experience.
