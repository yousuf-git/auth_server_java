package com.learning.security.models;

/*
 * ──────────────────────────────────────────────────────────────────
 * PLACEHOLDER: DB-backed OTP entity (not currently in use)
 * ──────────────────────────────────────────────────────────────────
 * OTP storage has been migrated to Redis for better performance
 * and automatic expiration. This entity is kept as a reference
 * for the data model in case DB-backed OTP storage is needed later.
 *
 * Fields reference:
 *   - id (Long)                : Primary key
 *   - user (User)              : FK to users table
 *   - codeHash (String)        : SHA-256 hash of the OTP code
 *   - type (OtpType)           : EMAIL_VERIFICATION or PASSWORD_RESET
 *   - expiresAt (Instant)      : When the OTP expires
 *   - used (Boolean)           : Whether the OTP has been consumed
 *   - attempts (Integer)       : Number of failed verification attempts
 *   - maxAttempts (Integer)    : Maximum allowed attempts (default 5)
 *   - ipAddress (String)       : IP address that requested the OTP
 *   - createdAt (Instant)      : Timestamp of creation
 *
 * See: OtpService (Redis-backed implementation)
 * See: OtpRepository (DB repository - not currently used)
 * ──────────────────────────────────────────────────────────────────
 */

// import com.learning.security.enums.OtpType;
// import jakarta.persistence.*;
// import lombok.*;
// import org.hibernate.annotations.CreationTimestamp;
// import java.time.Instant;
//
// @Data
// @NoArgsConstructor
// @AllArgsConstructor
// @Builder
// @Entity
// @Table(name = "otp_tokens", indexes = {
//     @Index(name = "idx_otp_user_id", columnList = "user_id"),
//     @Index(name = "idx_otp_type", columnList = "otp_type"),
//     @Index(name = "idx_otp_expires_at", columnList = "expires_at")
// })
// public class Otp {
//
//     @Id
//     @GeneratedValue(strategy = GenerationType.IDENTITY)
//     private Long id;
//
//     @ManyToOne(fetch = FetchType.LAZY)
//     @JoinColumn(name = "user_id", nullable = false)
//     private User user;
//
//     @Column(name = "code_hash", nullable = false, length = 64)
//     private String codeHash;
//
//     @Enumerated(EnumType.STRING)
//     @Column(name = "otp_type", nullable = false, length = 30)
//     private OtpType type;
//
//     @Column(name = "expires_at", nullable = false)
//     private Instant expiresAt;
//
//     @Builder.Default
//     @Column(name = "is_used", nullable = false)
//     private Boolean used = false;
//
//     @Builder.Default
//     @Column(name = "attempts", nullable = false)
//     private Integer attempts = 0;
//
//     @Builder.Default
//     @Column(name = "max_attempts", nullable = false)
//     private Integer maxAttempts = 5;
//
//     @Column(name = "ip_address", length = 45)
//     private String ipAddress;
//
//     @CreationTimestamp
//     @Column(name = "created_at", updatable = false)
//     private Instant createdAt;
//
//     public boolean isExpired() {
//         return Instant.now().isAfter(expiresAt);
//     }
//
//     public boolean isValid() {
//         return !used && !isExpired() && attempts < maxAttempts;
//     }
//
//     public void incrementAttempts() {
//         this.attempts++;
//     }
//
//     public void markAsUsed() {
//         this.used = true;
//     }
// }
