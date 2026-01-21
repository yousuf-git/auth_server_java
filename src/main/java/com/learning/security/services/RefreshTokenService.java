package com.learning.security.services;

import com.learning.security.dtos.TokenPair;
import com.learning.security.enums.RevocationReason;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.User;
import com.learning.security.repos.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * <h2>RefreshTokenService</h2>
 * <p>
 * Service for managing refresh tokens with security features:
 * - Token rotation (new token on each use)
 * - Family tracking (detect token theft)
 * - Max sessions per user (limit active sessions)
 * - Automatic cleanup (remove expired/revoked tokens)
 * </p>
 * 
 * <h3>Token Rotation Strategy:</h3>
 * <pre>
 * 1. Client sends refresh token
 * 2. Server validates token (not expired, not revoked)
 * 3. Server creates new refresh token (same family, incremented counter)
 * 4. Server revokes old refresh token
 * 5. Server returns new access token + new refresh token
 * 
 * If old token used again → Token theft detected → Revoke entire family
 * </pre>
 * 
 * <h3>Session Limit Strategy:</h3>
 * <pre>
 * - Max 10 active sessions per user
 * - When limit reached, revoke oldest session
 * - Each device gets separate session
 * </pre>
 */
@Service
public class RefreshTokenService {

    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);
    private static final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Value("${yousuf.app.refreshTokenExpirationTimeInMs:604800000}") // 7 days default
    private long refreshTokenExpirationMs;

    @Value("${yousuf.app.maxSessionsPerUser:5}")
    private int maxSessionsPerUser;

    /**
     * Create a new refresh token for user
     * 
     * @param user User for whom token is created
     * @param request HttpServletRequest to extract IP and user agent
     * @param oauthClientId OAuth2 client ID (null for local auth)
     * @return TokenPair containing entity and raw token
     */
    @Transactional
    public TokenPair createRefreshToken(User user, HttpServletRequest request, String oauthClientId) {
        // Check if user has reached max sessions limit
        enforceMaxSessions(user);

        // Generate opaque token (random bytes)
        String rawToken = generateOpaqueToken();
        String tokenHash = hashToken(rawToken);

        // Create token entity
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setId(UUID.randomUUID().toString());
        refreshToken.setUser(user);
        refreshToken.setOauthClientId(oauthClientId);
        refreshToken.setDeviceId(extractDeviceId(request));
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setIssuedAt(Instant.now());
        refreshToken.setExpiresAt(Instant.now().plusMillis(refreshTokenExpirationMs));
        refreshToken.setRotationCounter(0);
        refreshToken.setIpAddress(extractIpAddress(request));
        refreshToken.setUserAgent(extractUserAgent(request));
        refreshToken.setFamilyId(UUID.randomUUID().toString()); // New family for new login
        refreshToken.setParentId(null); // No parent for initial token
        refreshToken.setLastUsedAt(Instant.now());

        RefreshToken saved = refreshTokenRepository.save(refreshToken);
        
        logger.debug("Created refresh token for user: {} (family: {})", user.getEmail(), saved.getFamilyId());
        
        // Return both entity and raw token
        return new TokenPair(saved, rawToken);
    }

    /**
    /**
     * Validate and rotate refresh token
     * 
     * @param rawToken Raw refresh token from client
     * @param request HttpServletRequest for device tracking
     * @return TokenPair with new token and raw string
     * @throws RuntimeException if token invalid or revoked
     */
    @Transactional
    public TokenPair rotateRefreshToken(String rawToken, HttpServletRequest request) {
        String tokenHash = hashToken(rawToken);
        
        // Find token by hash
        RefreshToken currentToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        // Check if token is expired
        if (currentToken.isExpired()) {
            logger.warn("Expired refresh token used by user: {}", currentToken.getUser().getEmail());
            throw new RuntimeException("Refresh token expired. Please login again.");
        }

        // Smart theft detection based on revocation reason
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

        // Token is valid - proceed with rotation
        currentToken.markAsUsed();
        currentToken.revoke(RevocationReason.TOKEN_ROTATION); // Revoke current token with reason
        refreshTokenRepository.save(currentToken); // update current token

        // Create new token in same family
        String newRawToken = generateOpaqueToken();
        String newTokenHash = hashToken(newRawToken);

        RefreshToken newToken = new RefreshToken();
        newToken.setId(UUID.randomUUID().toString());
        newToken.setUser(currentToken.getUser());
        newToken.setOauthClientId(currentToken.getOauthClientId());
        newToken.setDeviceId(currentToken.getDeviceId());
        newToken.setTokenHash(newTokenHash);
        newToken.setIssuedAt(Instant.now());
        newToken.setExpiresAt(Instant.now().plusMillis(refreshTokenExpirationMs));
        newToken.setRotationCounter(currentToken.getRotationCounter() + 1);
        newToken.setIpAddress(extractIpAddress(request));
        newToken.setUserAgent(extractUserAgent(request));
        newToken.setFamilyId(currentToken.getFamilyId()); // Same family
        newToken.setParentId(currentToken.getId()); // Link to parent
        newToken.setLastUsedAt(Instant.now());

        RefreshToken saved = refreshTokenRepository.save(newToken);
        
        logger.debug("Rotated refresh token for user: {} (rotation: {})", 
            currentToken.getUser().getEmail(), saved.getRotationCounter());

        // Return both entity and raw token
        return new TokenPair(saved, newRawToken);
    }
    /**
     * Revoke a specific refresh token (e.g., during manual logout)
     */
    @Transactional
    public void revokeRefreshToken(String rawToken, RevocationReason reason) {
        String tokenHash = hashToken(rawToken);
        
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            token.revoke(reason);
            refreshTokenRepository.save(token);
            logger.debug("Revoked refresh token for user: {} (reason: {})", token.getUser().getEmail(), reason);
        });
    }

    /**
     * Revoke entire token family (used when token theft detected)
     */
    @Transactional
    public void revokeTokenFamily(String familyId, RevocationReason reason) {
        int revoked = refreshTokenRepository.revokeTokenFamily(familyId, Instant.now(), reason);
        logger.warn("Revoked token family {} with reason {} - {} tokens revoked", familyId, reason, revoked);
    }

    /**
     * Revoke all tokens for a user (logout all sessions)
     */
    @Transactional
    public void revokeAllUserTokens(Integer userId, RevocationReason reason) {
        int revoked = refreshTokenRepository.revokeAllUserTokens(userId, Instant.now(), reason);
        logger.info("Revoked all tokens for user {} with reason {} - {} tokens revoked", userId, reason, revoked);
    }

    /**
     * Get all active sessions for a user (for admin panel)
     */
    public List<RefreshToken> getActiveUserSessions(User user) {
        return refreshTokenRepository.findActiveSessionsByUser(user, Instant.now());
    }

    /**
     * Revoke a specific session by ID (admin operation)
     */
    @Transactional
    public void revokeSession(String sessionId, User user) {
        refreshTokenRepository.findByIdAndUser(sessionId, user).ifPresent(token -> {
            token.revoke(RevocationReason.ADMIN_REVOKED);
            refreshTokenRepository.save(token);
            logger.info("Admin revoked session {} for user {}", sessionId, user.getEmail());
        });
    }

    /**
     * Enforce max sessions per user
     * Revoke oldest session if limit reached
     */
    private void enforceMaxSessions(User user) {
        long activeSessionCount = refreshTokenRepository.countActiveSessionsByUserId(user.getId(), Instant.now());
        
        if (activeSessionCount >= maxSessionsPerUser) {
            // Find oldest token and revoke it
            List<RefreshToken> oldestTokens = refreshTokenRepository.findOldestActiveTokenByUserId(user.getId(), Instant.now());
            
            if (!oldestTokens.isEmpty()) {
                RefreshToken oldestToken = oldestTokens.get(0);
                oldestToken.revoke(RevocationReason.MAX_DEVICES_EXCEEDED);
                refreshTokenRepository.save(oldestToken);
                logger.info("Revoked oldest session for user {} (max sessions limit reached)", user.getEmail());
            }
        }
    }

    /**
     * Generate opaque refresh token (random 256-bit base64)
     */
    private String generateOpaqueToken() {
        byte[] randomBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Hash token using SHA-256
     * Never store plain tokens in database
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    /**
     * Convert byte array to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Extract IP address from request
     */
    private String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip != null ? ip : "unknown";
    }

    /**
     * Extract user agent from request
     */
    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "unknown";
    }

    /**
     * Extract device ID from request
     * Can be enhanced with device fingerprinting library
     */
    private String extractDeviceId(HttpServletRequest request) {
        // Simple device ID based on user agent hash
        String userAgent = extractUserAgent(request);
        String ip = extractIpAddress(request);
        String combined = userAgent + "|" + ip;
        return String.valueOf(combined.hashCode());
    }

    /**
     * Cleanup expired tokens older than 30 days
     * Called by scheduled task
     */
    @Transactional
    public int cleanupExpiredTokens() {
        Instant thirtyDaysAgo = Instant.now().minusSeconds(30 * 24 * 60 * 60);
        int deleted = refreshTokenRepository.deleteExpiredTokensOlderThan(thirtyDaysAgo);
        logger.info("Cleaned up {} expired tokens older than 30 days", deleted);
        return deleted;
    }

    /**
     * Cleanup revoked tokens older than 30 days
     * Called by scheduled task
     */
    @Transactional
    public int cleanupRevokedTokens() {
        Instant thirtyDaysAgo = Instant.now().minusSeconds(30 * 24 * 60 * 60);
        int deleted = refreshTokenRepository.deleteRevokedTokensOlderThan(thirtyDaysAgo);
        logger.info("Cleaned up {} revoked tokens older than 30 days", deleted);
        return deleted;
    }
    /**
     * Get user from refresh token (for validation)
     */
    public User getUserFromRefreshToken(String rawToken) {
        String tokenHash = hashToken(rawToken);
        RefreshToken token = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
        
        if (token.isExpired() || token.isRevoked()) {
            throw new RuntimeException("Refresh token is not valid");
        }
        
        return token.getUser();
    }
}   

