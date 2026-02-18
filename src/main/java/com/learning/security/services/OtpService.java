package com.learning.security.services;

import com.learning.security.enums.OtpType;
import com.learning.security.exceptions.OtpException;
import com.learning.security.models.User;
import com.learning.security.services.email.EmailService;
import com.learning.security.services.email.EmailTemplateService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;

@Service
@Slf4j
public class OtpService {

    private static final SecureRandom secureRandom = new SecureRandom();

    // Redis key prefixes
    private static final String OTP_KEY_PREFIX = "otp:";           // otp:{type}:{email} -> hashed code
    private static final String OTP_ATTEMPTS_PREFIX = "otp:att:";  // otp:att:{type}:{email} -> attempt count
    private static final String OTP_RATE_PREFIX = "otp:rate:";     // otp:rate:{type}:{email} -> request count in current hour
    private static final String OTP_COOLDOWN_PREFIX = "otp:cd:";   // otp:cd:{type}:{email} -> cooldown marker

    @Autowired
    private StringRedisTemplate redisTemplate;

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

    public void sendVerificationOtp(User user, HttpServletRequest request) {
        checkRateLimit(user.getEmail(), OtpType.EMAIL_VERIFICATION);

        String code = generateOtpCode();
        storeOtp(user.getEmail(), code, OtpType.EMAIL_VERIFICATION);

        String htmlBody = emailTemplateService.buildVerificationEmail(
                user.getFirstName(), code, otpExpiryMinutes);
        emailService.sendEmail(user.getEmail(), "Verify Your Email Address", htmlBody);

        log.info("Verification OTP sent to: {}", user.getEmail());
    }

    public void sendPasswordResetOtp(User user, HttpServletRequest request) {
        checkRateLimit(user.getEmail(), OtpType.PASSWORD_RESET);

        String code = generateOtpCode();
        storeOtp(user.getEmail(), code, OtpType.PASSWORD_RESET);

        String htmlBody = emailTemplateService.buildPasswordResetEmail(
                user.getFirstName(), code, otpExpiryMinutes);
        emailService.sendEmail(user.getEmail(), "Reset Your Password", htmlBody);

        log.info("Password reset OTP sent to: {}", user.getEmail());
    }

    // ──────────────────────────── Verify OTP ────────────────────────────

    public boolean verifyOtp(String email, String code, OtpType type) {
        String otpKey = otpKey(type, email);
        String attemptsKey = attemptsKey(type, email);

        String storedHash = redisTemplate.opsForValue().get(otpKey);
        if (storedHash == null) {
            throw new OtpException("OTP expired or not found. Please request a new one.");
        }

        // Check attempts
        String attemptsStr = redisTemplate.opsForValue().get(attemptsKey);
        int attempts = attemptsStr != null ? Integer.parseInt(attemptsStr) : 0;

        if (attempts >= maxAttempts) {
            // Invalidate the OTP
            redisTemplate.delete(otpKey);
            redisTemplate.delete(attemptsKey);
            throw new OtpException("Maximum verification attempts exceeded. Please request a new OTP.");
        }

        if (!hashOtpCode(code).equals(storedHash)) {
            // Increment attempts
            redisTemplate.opsForValue().increment(attemptsKey);
            // Set TTL on attempts key to match OTP expiry if first attempt
            if (attempts == 0) {
                redisTemplate.expire(attemptsKey, Duration.ofMinutes(otpExpiryMinutes));
            }
            int remaining = maxAttempts - attempts - 1;
            throw new OtpException("Invalid OTP. " + remaining + " attempt(s) remaining.");
        }

        // OTP is valid — clean up
        redisTemplate.delete(otpKey);
        redisTemplate.delete(attemptsKey);
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

    // ──────────────────────────── Helpers ────────────────────────────

    private void checkRateLimit(String email, OtpType type) {
        String cooldownKey = cooldownKey(type, email);
        String rateKey = rateKey(type, email);

        // Check cooldown between consecutive OTPs
        if (Boolean.TRUE.equals(redisTemplate.hasKey(cooldownKey))) {
            Long ttl = redisTemplate.getExpire(cooldownKey);
            long secondsRemaining = ttl != null && ttl > 0 ? ttl : cooldownSeconds;
            throw new OtpException("Please wait " + secondsRemaining + " seconds before requesting a new OTP.");
        }

        // Check hourly limit
        String countStr = redisTemplate.opsForValue().get(rateKey);
        int count = countStr != null ? Integer.parseInt(countStr) : 0;
        if (count >= maxPerHour) {
            throw new OtpException("Too many OTP requests. Please try again later.");
        }

        // Increment rate counter
        redisTemplate.opsForValue().increment(rateKey);
        if (count == 0) {
            redisTemplate.expire(rateKey, Duration.ofHours(1));
        }

        // Set cooldown marker
        redisTemplate.opsForValue().set(cooldownKey, "1", Duration.ofSeconds(cooldownSeconds));
    }

    private void storeOtp(String email, String code, OtpType type) {
        String otpKey = otpKey(type, email);
        String attemptsKey = attemptsKey(type, email);

        // Store hashed OTP with TTL
        redisTemplate.opsForValue().set(otpKey, hashOtpCode(code), Duration.ofMinutes(otpExpiryMinutes));

        // Reset attempts counter
        redisTemplate.delete(attemptsKey);
    }

    private String generateOtpCode() {
        int code = 100_000 + secureRandom.nextInt(900_000);
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

    // ──────────────────────────── Key Builders ────────────────────────────

    private String otpKey(OtpType type, String email) {
        return OTP_KEY_PREFIX + type.name().toLowerCase() + ":" + email.toLowerCase();
    }

    private String attemptsKey(OtpType type, String email) {
        return OTP_ATTEMPTS_PREFIX + type.name().toLowerCase() + ":" + email.toLowerCase();
    }

    private String rateKey(OtpType type, String email) {
        return OTP_RATE_PREFIX + type.name().toLowerCase() + ":" + email.toLowerCase();
    }

    private String cooldownKey(OtpType type, String email) {
        return OTP_COOLDOWN_PREFIX + type.name().toLowerCase() + ":" + email.toLowerCase();
    }
}
