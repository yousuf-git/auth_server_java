package com.learning.security.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * <h2>SessionInfo</h2>
 * <p>
 * DTO for user session information (admin panel)
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SessionInfo {
    
    /**
     * Session ID (refresh token ID)
     */
    private String sessionId;
    
    /**
     * Device ID
     */
    private String deviceId;
    
    /**
     * IP address
     */
    private String ipAddress;
    
    /**
     * User agent (browser/device info)
     */
    private String userAgent;
    
    /**
     * When session was created
     */
    private Instant createdAt;
    
    /**
     * When session was last used
     */
    private Instant lastUsedAt;
    
    /**
     * When session expires
     */
    private Instant expiresAt;
    
    /**
     * OAuth2 client ID (if applicable)
     */
    private String oauthClientId;
    
    /**
     * Number of times token has been rotated
     */
    private Integer rotationCount;
    
    /**
     * Is this the current session?
     */
    private Boolean current;
}
