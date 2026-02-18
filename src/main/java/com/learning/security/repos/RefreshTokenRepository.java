package com.learning.security.repos;

import com.learning.security.enums.RevocationReason;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * <h2>RefreshTokenRepository</h2>
 * <p>
 * Repository for managing refresh tokens with support for:
 * - Token lookup by hash
 * - Session management per user
 * - Family-based token revocation (token theft detection)
 * - Cleanup of expired/revoked tokens
 * </p>
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    /**
     * Find token by its hash
     * Used during token refresh to validate incoming token
     */
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Find all active tokens for a user
     * Active = not expired and not revoked
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId " +
           "AND rt.revokedAt IS NULL AND rt.expiresAt > :now")
       List<RefreshToken> findActiveTokensByUserId(@Param("userId") Integer userId, @Param("now") Instant now);

    /**
     * Find all tokens in a family
     * Used to revoke entire family when token theft detected
     */
    List<RefreshToken> findByFamilyId(String familyId);

    /**
     * Count active sessions for a user
     * Used to enforce max sessions limit
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user.id = :userId " +
           "AND rt.revokedAt IS NULL AND rt.expiresAt > :now")
       long countActiveSessionsByUserId(@Param("userId") Integer userId, @Param("now") Instant now);

    /**
     * Find oldest active token for a user
     * Used to revoke oldest session when max sessions limit reached
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId " +
           "AND rt.revokedAt IS NULL AND rt.expiresAt > :now " +
           "ORDER BY rt.issuedAt ASC")
       List<RefreshToken> findOldestActiveTokenByUserId(@Param("userId") Integer userId, @Param("now") Instant now);

    /**
     * Revoke all tokens in a family
     * Used when token theft detected (old token reused)
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revokedAt = :revokedAt, rt.revocationReason = :reason WHERE rt.familyId = :familyId AND rt.revokedAt IS NULL")
    int revokeTokenFamily(@Param("familyId") String familyId, @Param("revokedAt") Instant revokedAt, @Param("reason") RevocationReason reason);

    /**
     * Revoke all tokens for a user
     * Used during logout all sessions
     */
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revokedAt = :revokedAt, rt.revocationReason = :reason WHERE rt.user.id = :userId AND rt.revokedAt IS NULL")
       int revokeAllUserTokens(@Param("userId") Integer userId, @Param("revokedAt") Instant revokedAt, @Param("reason") RevocationReason reason);

    /**
     * Delete expired tokens older than specified date
     * Used by scheduled cleanup task
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :expirationDate")
    int deleteExpiredTokensOlderThan(@Param("expirationDate") Instant expirationDate);

    /**
     * Delete revoked tokens older than specified date
     * Used by scheduled cleanup task
     */
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.revokedAt IS NOT NULL AND rt.revokedAt < :revocationDate")
    int deleteRevokedTokensOlderThan(@Param("revocationDate") Instant revocationDate);

    /**
     * Find all active tokens for a user (for admin session management)
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user = :user " +
           "AND rt.revokedAt IS NULL AND rt.expiresAt > :now " +
           "ORDER BY rt.lastUsedAt DESC")
    List<RefreshToken> findActiveSessionsByUser(@Param("user") User user, @Param("now") Instant now);

    /**
     * Find all active sessions across all users (for admin dashboard)
     */
    @Query("SELECT rt FROM RefreshToken rt JOIN FETCH rt.user WHERE rt.revokedAt IS NULL AND rt.expiresAt > :now ORDER BY rt.lastUsedAt DESC")
    List<RefreshToken> findAllActiveSessions(@Param("now") Instant now);

    /**
     * Count all active sessions across all users
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.revokedAt IS NULL AND rt.expiresAt > :now")
    long countAllActiveSessions(@Param("now") Instant now);

    /**
     * Count distinct users with active sessions
     */
    @Query("SELECT COUNT(DISTINCT rt.user.id) FROM RefreshToken rt WHERE rt.revokedAt IS NULL AND rt.expiresAt > :now")
    long countUsersWithActiveSessions(@Param("now") Instant now);

    /**
     * Check if token exists by hash
     */
    boolean existsByTokenHash(String tokenHash);

    /**
     * Find token by ID and user (for admin operations)
     */
    Optional<RefreshToken> findByIdAndUser(String id, User user);
}
