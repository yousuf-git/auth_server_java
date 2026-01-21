package com.learning.security.enums;

/**
 * <h2>RevocationReason</h2>
 * <p>
 * Enum representing different reasons why a refresh token was revoked.
 * Used to differentiate between legitimate revocations and security threats.
 * </p>
 */
public enum RevocationReason {
    /**
     * Token rotated during normal refresh flow
     */
    TOKEN_ROTATION,
    
    /**
     * User explicitly logged out from this session
     */
    MANUAL_LOGOUT,
    
    /**
     * Session revoked due to max device limit reached
     * This is a legitimate revocation, not a security threat
     */
    MAX_DEVICES_EXCEEDED,
    
    /**
     * Token theft detected - revoked token was reused
     * This is a security incident
     */
    THEFT_DETECTED,
    
    /**
     * Admin manually revoked the session
     */
    ADMIN_REVOKED
}
