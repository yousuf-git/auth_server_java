package com.learning.security.scheduler;

import com.learning.security.services.RefreshTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * <h2>TokenCleanupScheduler</h2>
 * <p>
 * Scheduled task to periodically clean up expired and revoked refresh tokens
 * Prevents database bloat by removing old tokens that are no longer needed
 * </p>
 */
@Component
public class TokenCleanupScheduler {

    private static final Logger logger = LoggerFactory.getLogger(TokenCleanupScheduler.class);

    @Autowired
    private RefreshTokenService refreshTokenService;

    /**
     * Clean up expired tokens older than 30 days
     * Runs daily at 2:00 AM
     */
    @Scheduled(cron = "0 0 2 * * *")
    public void cleanupExpiredTokens() {
        logger.info("Starting scheduled cleanup of expired tokens");
        try {
            int deletedCount = refreshTokenService.cleanupExpiredTokens();
            logger.info("Successfully deleted {} expired tokens", deletedCount);
        } catch (Exception e) {
            logger.error("Error during expired token cleanup", e);
        }
    }

    /**
     * Clean up revoked tokens older than 30 days
     * Runs daily at 2:30 AM
     */
    @Scheduled(cron = "0 30 2 * * *")
    public void cleanupRevokedTokens() {
        logger.info("Starting scheduled cleanup of revoked tokens");
        try {
            int deletedCount = refreshTokenService.cleanupRevokedTokens();
            logger.info("Successfully deleted {} revoked tokens", deletedCount);
        } catch (Exception e) {
            logger.error("Error during revoked token cleanup", e);
        }
    }

    /**
     * Log token statistics
     * Runs every hour
     */
    @Scheduled(cron = "0 0 * * * *")
    public void logTokenStatistics() {
        // This can be implemented later to track token usage patterns
        logger.debug("Token cleanup scheduler is active");
    }
}
