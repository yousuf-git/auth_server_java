package com.learning.security.repos;

/*
 * ──────────────────────────────────────────────────────────────────
 * PLACEHOLDER: DB-backed OTP repository (not currently in use)
 * ──────────────────────────────────────────────────────────────────
 * OTP storage has been migrated to Redis via OtpService.
 * This repository is kept as a reference in case DB-backed
 * OTP storage is needed in the future.
 *
 * See: OtpService for the current Redis-backed implementation
 * See: Otp entity (models/Otp.java) for the data model reference
 * ──────────────────────────────────────────────────────────────────
 */

// import com.learning.security.enums.OtpType;
// import com.learning.security.models.Otp;
// import com.learning.security.models.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Modifying;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;
// import org.springframework.stereotype.Repository;
//
// import java.time.Instant;
// import java.util.Optional;
//
// @Repository
// public interface OtpRepository extends JpaRepository<Otp, Long> {
//
//     Optional<Otp> findTopByUserAndTypeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(
//             User user, OtpType type, Instant now);
//
//     @Query("SELECT COUNT(o) FROM Otp o WHERE o.user = :user AND o.type = :type AND o.createdAt > :since")
//     long countRecentOtps(@Param("user") User user, @Param("type") OtpType type, @Param("since") Instant since);
//
//     @Modifying
//     @Query("UPDATE Otp o SET o.used = true WHERE o.user = :user AND o.type = :type AND o.used = false")
//     int invalidateAllOtps(@Param("user") User user, @Param("type") OtpType type);
//
//     @Modifying
//     @Query("DELETE FROM Otp o WHERE o.expiresAt < :now OR o.used = true")
//     int cleanupExpiredAndUsedOtps(@Param("now") Instant now);
// }
