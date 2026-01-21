package com.learning.security.models;

import com.learning.security.enums.RevocationReason;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * <h2>RefreshToken</h2>
 * <p>
 * Entity representing a refresh token with rotation and family tracking for security.
 * Supports multi-device sessions with token theft detection.
 * </p>
 * 
 * <h3>Security Features:</h3>
 * <ul>
 *   <li>Token rotation - new refresh token issued on each use</li>
 *   <li>Family tracking - detect reuse of revoked tokens (token theft)</li>
 *   <li>Device tracking - separate sessions per device</li>
 *   <li>Max sessions per user - limit active sessions</li>
 *   <li>Automatic expiration - 7-day lifetime (configurable)</li>
 * </ul>
 * 
 * <h3>Token Rotation Flow:</h3>
 * <pre>
 * Login → Token A (family_id=F1, parent_id=null)
 * Refresh → Token B (family_id=F1, parent_id=A, rotation_counter++)
 * Refresh → Token C (family_id=F1, parent_id=B, rotation_counter++)
 * 
 * If Token A or B is reused → Revoke entire family (token theft detected)
 * </pre>
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
    @Index(name = "idx_token_hash", columnList = "token_hash"),
    @Index(name = "idx_user_id", columnList = "user_id"),
    @Index(name = "idx_family_id", columnList = "family_id"),
    @Index(name = "idx_expires_at", columnList = "expires_at"),
    @Index(name = "idx_revoked_at", columnList = "revoked_at")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {

    /**
     * Unique identifier (JWT ID - jti)
     */
    @Id
    @Column(name = "id", nullable = false, unique = true)
    private String id = UUID.randomUUID().toString();

    /**
     * User who owns this token
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    /**
     * OAuth2 client ID (if applicable)
     * Null for local authentication
     */
    @Column(name = "oauth_client_id", length = 100)
    private String oauthClientId;

    /**
     * Device identifier (browser fingerprint or device ID)
     */
    @Column(name = "device_id", length = 255)
    private String deviceId;

    /**
     * Hashed refresh token (SHA-256)
     * Never store plain tokens in database
     */
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    /**
     * When token was issued
     */
    @Column(name = "issued_at", nullable = false)
    private Instant issuedAt;

    /**
     * When token expires (from issuedAt)
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    /**
     * When token was revoked (null if active)
     * Used for logout and token rotation
     */
    @Column(name = "revoked_at")
    private Instant revokedAt;

    /**
     * Reason why token was revoked
     * Used to differentiate between legitimate revocation and security threats
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason", length = 30)
    private RevocationReason revocationReason;

    /**
     * Number of times this token family has been rotated
     * Incremented on each refresh
     */
    @Column(name = "rotation_counter", nullable = false)
    private Integer rotationCounter = 0;

    /**
     * IP address from which token was issued
     */
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    /**
     * User agent (browser/device info)
     */
    @Column(name = "user_agent", length = 500)
    private String userAgent;

    /**
     * Family ID - groups related tokens from same login session
     * When token theft detected, entire family is revoked
     */
    @Column(name = "family_id", nullable = false, length = 36)
    private String familyId;

    /**
     * Parent token ID - the token that was rotated to create this one
     * Null for initial login token
     */
    @Column(name = "parent_id", length = 36)
    private String parentId;

    /**
     * When token was last used
     * Updated on each successful refresh
     */
    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * Check if token is revoked
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * Check if token is active (not expired and not revoked)
     */
    public boolean isActive() {
        return !isExpired() && !isRevoked();
    }

    /**
     * Revoke this token with a reason
     */
    public void revoke(RevocationReason reason) {
        this.revokedAt = Instant.now();
        this.revocationReason = reason;
    }

    /**
     * Revoke this token (default to TOKEN_ROTATION)
     */
    public void revoke() {
        revoke(RevocationReason.TOKEN_ROTATION);
    }

    /**
     * Update last used timestamp
     */
    public void markAsUsed() {
        this.lastUsedAt = Instant.now();
    }
}
