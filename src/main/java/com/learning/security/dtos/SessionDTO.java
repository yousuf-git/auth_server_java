package com.learning.security.dtos;

import com.learning.security.models.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * DTO for representing user session information
 * Used in session management APIs for both users and admins
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionDTO {
    
    private String sessionId;
    private String deviceId;
    private String ipAddress;
    private String userAgent;
    private Instant issuedAt;
    private Instant lastUsedAt;
    private Instant expiresAt;
    private boolean isCurrentSession;
    
    // For admin view - includes user info
    private Integer userId;
    private String userEmail;

    /**
     * Create SessionDTO from RefreshToken entity (for user's own sessions)
     */
    public static SessionDTO fromRefreshToken(RefreshToken token, String currentTokenHash) {
        return SessionDTO.builder()
                .sessionId(token.getId())
                .deviceId(token.getDeviceId())
                .ipAddress(token.getIpAddress())
                .userAgent(parseUserAgent(token.getUserAgent()))
                .issuedAt(token.getIssuedAt())
                .lastUsedAt(token.getLastUsedAt())
                .expiresAt(token.getExpiresAt())
                .isCurrentSession(token.getTokenHash().equals(currentTokenHash))
                .build();
    }

    /**
     * Create SessionDTO from RefreshToken entity (for admin view with user info)
     */
    public static SessionDTO fromRefreshTokenForAdmin(RefreshToken token) {
        return SessionDTO.builder()
                .sessionId(token.getId())
                .deviceId(token.getDeviceId())
                .ipAddress(token.getIpAddress())
                .userAgent(parseUserAgent(token.getUserAgent()))
                .issuedAt(token.getIssuedAt())
                .lastUsedAt(token.getLastUsedAt())
                .expiresAt(token.getExpiresAt())
                .userId(token.getUser().getId())
                .userEmail(token.getUser().getEmail())
                .isCurrentSession(false) // Admin doesn't have a "current" session in this context
                .build();
    }

    /**
     * Parse user agent string to extract browser/device info
     */
    private static String parseUserAgent(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "Unknown Device";
        }
        
        // Simple parsing - extract browser name
        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) {
            return "Chrome - " + extractOS(userAgent);
        } else if (userAgent.contains("Firefox")) {
            return "Firefox - " + extractOS(userAgent);
        } else if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) {
            return "Safari - " + extractOS(userAgent);
        } else if (userAgent.contains("Edg")) {
            return "Edge - " + extractOS(userAgent);
        } else if (userAgent.contains("PostmanRuntime")) {
            return "Postman";
        }
        
        return userAgent.length() > 50 ? userAgent.substring(0, 50) + "..." : userAgent;
    }

    private static String extractOS(String userAgent) {
        if (userAgent.contains("Windows")) return "Windows";
        if (userAgent.contains("Mac OS")) return "macOS";
        if (userAgent.contains("Linux")) return "Linux";
        if (userAgent.contains("Android")) return "Android";
        if (userAgent.contains("iPhone") || userAgent.contains("iPad")) return "iOS";
        return "Unknown OS";
    }
}
