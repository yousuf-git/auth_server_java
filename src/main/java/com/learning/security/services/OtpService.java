package com.learning.security.services;

import com.learning.security.enums.OtpType;
import com.learning.security.exceptions.OtpException;
import com.learning.security.models.Otp;
import com.learning.security.models.User;
import com.learning.security.repos.OtpRepository;
import com.learning.security.services.email.EmailService;
import com.learning.security.services.email.EmailTemplateService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
@Slf4j
public class OtpService {

    private static final SecureRandom secureRandom = new SecureRandom();

    @Autowired
    private OtpRepository otpRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private EmailTemplateService emailTemplateService;

    @Value("${yousuf.app.otp.expiry-minutes:10}")
    private int otpExpiryMinutes;

    @Value("${yousuf.app.otp.max-attempts:5}")
    private int maxAttempts;

    @Value("${yousuf.app.otp.cooldown-seconds:60}")
    private int cooldownSeconds;

    @Value("${yousuf.app.otp.max-per-hour:5}")
    private int maxPerHour;

    // ──────────────────────────── Send OTPs ────────────────────────────

    @Transactional
    public void sendVerificationOtp(User user, HttpServletRequest request) {
        checkRateLimit(user, OtpType.EMAIL_VERIFICATION);

        // Invalidate any previous unused OTPs
        otpRepository.invalidateAllOtps(user, OtpType.EMAIL_VERIFICATION);

        String code = generateOtpCode();
        saveOtp(user, code, OtpType.EMAIL_VERIFICATION, request);

        String htmlBody = emailTemplateService.buildVerificationEmail(
                user.getFirstName(), code, otpExpiryMinutes);
        emailService.sendEmail(user.getEmail(), "Verify Your Email Address", htmlBody);

        log.info("Verification OTP sent to: {}", user.getEmail());
    }

    @Transactional
    public void sendPasswordResetOtp(User user, HttpServletRequest request) {
        checkRateLimit(user, OtpType.PASSWORD_RESET);

        // Invalidate any previous unused OTPs
        otpRepository.invalidateAllOtps(user, OtpType.PASSWORD_RESET);

        String code = generateOtpCode();
        saveOtp(user, code, OtpType.PASSWORD_RESET, request);

        String htmlBody = emailTemplateService.buildPasswordResetEmail(
                user.getFirstName(), code, otpExpiryMinutes);
        emailService.sendEmail(user.getEmail(), "Reset Your Password", htmlBody);

        log.info("Password reset OTP sent to: {}", user.getEmail());
    }

    // ──────────────────────────── Verify OTP ────────────────────────────

    @Transactional
    public boolean verifyOtp(User user, String code, OtpType type) {
        Otp otp = otpRepository
                .findTopByUserAndTypeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(user, type, Instant.now())
                .orElseThrow(() -> new OtpException("No valid OTP found. Please request a new one."));

        if (otp.getAttempts() >= otp.getMaxAttempts()) {
            otp.markAsUsed();
            otpRepository.save(otp);
            throw new OtpException("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        if (!hashOtpCode(code).equals(otp.getCodeHash())) {
            otp.incrementAttempts();
            otpRepository.save(otp);
            int remaining = otp.getMaxAttempts() - otp.getAttempts();
            throw new OtpException("Invalid OTP. " + remaining + " attempt(s) remaining.");
        }

        otp.markAsUsed();
        otpRepository.save(otp);
        return true;
    }

    // ──────────────────────────── Notification Emails ────────────────────────────

    public void sendPasswordChangedNotification(User user) {
        try {
            String htmlBody = emailTemplateService.buildPasswordChangedEmail(user.getFirstName());
            emailService.sendEmail(user.getEmail(), "Your Password Has Been Changed", htmlBody);
        } catch (Exception e) {
            log.error("Failed to send password changed notification to: {}", user.getEmail(), e);
        }
    }

    public void sendWelcomeEmail(User user) {
        try {
            String htmlBody = emailTemplateService.buildWelcomeEmail(user.getFirstName());
            emailService.sendEmail(user.getEmail(), "Welcome! Your Email Has Been Verified", htmlBody);
        } catch (Exception e) {
            log.error("Failed to send welcome email to: {}", user.getEmail(), e);
        }
    }

    // ──────────────────────────── Cleanup ────────────────────────────

    @Transactional
    public int cleanupOtps() {
        int deleted = otpRepository.cleanupExpiredAndUsedOtps(Instant.now());
        log.info("Cleaned up {} expired/used OTP tokens", deleted);
        return deleted;
    }

    // ──────────────────────────── Helpers ────────────────────────────

    private void checkRateLimit(User user, OtpType type) {
        // Check hourly limit
        long recentCount = otpRepository.countRecentOtps(user, type, Instant.now().minus(1, ChronoUnit.HOURS));
        if (recentCount >= maxPerHour) {
            throw new OtpException("Too many OTP requests. Please try again later.");
        }

        // Check cooldown between consecutive OTPs
        otpRepository
                .findTopByUserAndTypeAndUsedFalseAndExpiresAtAfterOrderByCreatedAtDesc(user, type, Instant.now())
                .ifPresent(lastOtp -> {
                    Instant cooldownEnd = lastOtp.getCreatedAt().plus(cooldownSeconds, ChronoUnit.SECONDS);
                    if (Instant.now().isBefore(cooldownEnd)) {
                        long secondsRemaining = Instant.now().until(cooldownEnd, ChronoUnit.SECONDS);
                        throw new OtpException(
                                "Please wait " + secondsRemaining + " seconds before requesting a new OTP.");
                    }
                });
    }

    private void saveOtp(User user, String code, OtpType type, HttpServletRequest request) {
        Otp otp = Otp.builder()
                .user(user)
                .codeHash(hashOtpCode(code))
                .type(type)
                .expiresAt(Instant.now().plus(otpExpiryMinutes, ChronoUnit.MINUTES))
                .maxAttempts(maxAttempts)
                .ipAddress(extractIpAddress(request))
                .build();

        otpRepository.save(otp);
    }

    private String generateOtpCode() {
        int code = 100_000 + secureRandom.nextInt(900_000); // 6-digit code
        return String.valueOf(code);
    }

    private String hashOtpCode(String code) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(code.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to hash OTP code", e);
        }
    }

    private String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty()) ip = request.getHeader("X-Real-IP");
        if (ip == null || ip.isEmpty()) ip = request.getRemoteAddr();
        return ip != null ? ip : "unknown";
    }
}
