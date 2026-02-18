package com.learning.security.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.learning.security.dtos.LoginRequest;
import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SignUpRequest;
import com.learning.security.dtos.TokenPair;
import com.learning.security.auth.AuthEntryPointJwt;
import com.learning.security.dtos.ForgotPasswordRequest;
import com.learning.security.dtos.ResetPasswordRequest;
import com.learning.security.dtos.VerifyEmailRequest;
import com.learning.security.dtos.ResendOtpRequest;
import com.learning.security.enums.AuthProvider;
import com.learning.security.enums.OtpType;
import com.learning.security.enums.RevocationReason;
import com.learning.security.exceptions.OtpException;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.payload.response.AuthResponse;
import com.learning.security.services.OtpService;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.RoleService;
import com.learning.security.services.UserService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.CookieUtils;
import com.learning.security.utils.JwtUtils;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
// @CrossOrigin(originPatterns = "*", maxAge = 3600, allowCredentials = "true") // Allow credentials for cookies, maxAge is in seconds; 3600s = 1 hr
/*
 * The HTTP Access-Control-Max-Age response header indicates how long the
 * results of a preflight request (that is, the information contained in the
 * Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be
 * cached.
 */
// https://docs.spring.io/spring-framework/docs/4.2.x/spring-framework-reference/html/cors.html
public class AuthController {

    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleService roleService;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    CookieUtils cookieUtils;

    @Autowired
    OtpService otpService;

    org.slf4j.Logger log = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignUpRequest request,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        if (userService.existsByEmail(request.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("Email already exists !"), HttpStatus.BAD_REQUEST);
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setPhone(request.getPhone());
        user.setProvider(AuthProvider.LOCAL);

        // Flexible role assignment: look up by name from DB, no hardcoded defaults
        if (request.getRole() != null && !request.getRole().isBlank()) {
            Role role = roleService.findByName(request.getRole()).orElse(null);
            if (role == null) {
                return new ResponseEntity<>(new ResponseMessage("Role '" + request.getRole() + "' not found!"),
                        HttpStatus.BAD_REQUEST);
            }
            user.setRole(role);
        }
        // If no role provided, user is created without a role (can be assigned later)

        User savedUser = userService.save(user);

        // Send email verification OTP (non-blocking: log error if email fails)
        try {
            otpService.sendVerificationOtp(savedUser, httpRequest);
        } catch (Exception e) {
            log.warn("Failed to send verification email to {}: {}", savedUser.getEmail(), e.getMessage());
        }

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            TokenPair tokenPair = refreshTokenService.createRefreshToken(savedUser, httpRequest, null);
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                userDetails.getId(),
                userDetails.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs(),
                savedUser.getEmailVerified()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.CREATED);

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("User created but authentication failed"));
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@Valid @RequestBody LoginRequest loginRequest,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        // Check if user exists first to provide specific error message
        if (!userService.existsByEmail(loginRequest.getEmail())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Email not registered"));
        }

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            TokenPair tokenPair = refreshTokenService.createRefreshToken(
                userService.findById(userDetails.getId()).orElseThrow(),
                httpRequest,
                null
            );
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

            User user = userService.findById(userDetails.getId()).orElseThrow();
            AuthResponse authResponse = new AuthResponse(
                accessToken,
                userDetails.getId(),
                userDetails.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs(),
                user.getEmailVerified()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.OK);

        } catch (LockedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ResponseMessage("Account is locked. Please contact administrator."));
        } catch (AuthenticationException e) {
            log.error("Failed login attempt for email {}: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid password"));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ResponseMessage("Refresh token not found"));
            }

            // Rotate refresh token (validates and creates new one)
            TokenPair tokenPair = refreshTokenService.rotateRefreshToken(refreshToken, request);

            cookieUtils.setRefreshTokenCookie(response, tokenPair.getRawToken());

            User user = tokenPair.getRefreshToken().getUser();
            Authentication authentication = createAuthenticationFromUser(user);
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            String role = user.getRole() != null ? user.getRole().getName() : "";

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                user.getId(),
                user.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs(),
                user.getEmailVerified()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.OK);

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            // Token invalid, expired, or theft detected
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Session expired. Please login again."));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken != null) {
                refreshTokenService.revokeRefreshToken(refreshToken, RevocationReason.MANUAL_LOGOUT);
            }

            cookieUtils.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));
        }
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken != null) {
                User user = refreshTokenService.getUserFromRefreshToken(refreshToken);
                refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.MANUAL_LOGOUT);
            }

            cookieUtils.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(new ResponseMessage("Logged out from all devices"));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid session"));
        }
    }

    // ──────────────────────────── Forgot Password ────────────────────────────

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                            HttpServletRequest httpRequest) {
        // Always return success to prevent email enumeration
        String genericMessage = "If an account exists with this email, we've sent a password reset code.";

        try {
            User user = userService.findByEmail(request.getEmail()).orElse(null);

            if (user == null) {
                return ResponseEntity.ok(new ResponseMessage(genericMessage));
            }

            // Only LOCAL users can reset password; OAuth users should use their provider
            if (user.getProvider() != null && user.getProvider() != AuthProvider.LOCAL) {
                return ResponseEntity.ok(new ResponseMessage(genericMessage));
            }

            otpService.sendPasswordResetOtp(user, httpRequest);
        } catch (OtpException e) {
            // Rate limit hit — still return generic message for security, but log it
            log.warn("Forgot-password rate limited for {}: {}", request.getEmail(), e.getMessage());
        } catch (Exception e) {
            log.error("Error in forgot-password for {}: {}", request.getEmail(), e.getMessage());
        }

        return ResponseEntity.ok(new ResponseMessage(genericMessage));
    }

    // ──────────────────────────── Reset Password ────────────────────────────

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        User user = userService.findByEmail(request.getEmail())
                .orElseThrow(() -> new OtpException("Invalid email or OTP."));

        // Verify OTP
        otpService.verifyOtp(user, request.getOtp(), OtpType.PASSWORD_RESET);

        // Update password
        user.setPassword(encoder.encode(request.getNewPassword()));
        userService.save(user);

        // Revoke all sessions for security (force re-login)
        refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.ADMIN_REVOKED);

        // Send notification email
        otpService.sendPasswordChangedNotification(user);

        return ResponseEntity.ok(new ResponseMessage("Password has been reset successfully. Please login with your new password."));
    }

    // ──────────────────────────── Email Verification ────────────────────────────

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody VerifyEmailRequest request) {
        User user = userService.findByEmail(request.getEmail())
                .orElseThrow(() -> new OtpException("User not found."));

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            return ResponseEntity.ok(new ResponseMessage("Email is already verified."));
        }

        otpService.verifyOtp(user, request.getOtp(), OtpType.EMAIL_VERIFICATION);

        user.setEmailVerified(true);
        userService.save(user);

        // Send welcome email
        otpService.sendWelcomeEmail(user);

        return ResponseEntity.ok(new ResponseMessage("Email verified successfully!"));
    }

    // ──────────────────────────── Resend OTP ────────────────────────────

    @PostMapping("/resend-otp")
    public ResponseEntity<?> resendOtp(@Valid @RequestBody ResendOtpRequest request,
                                       HttpServletRequest httpRequest) {
        OtpType otpType;
        try {
            otpType = OtpType.valueOf(request.getType().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(new ResponseMessage("Invalid OTP type. Use EMAIL_VERIFICATION or PASSWORD_RESET."));
        }

        User user = userService.findByEmail(request.getEmail()).orElse(null);

        // Don't reveal if user exists for PASSWORD_RESET
        if (user == null) {
            if (otpType == OtpType.PASSWORD_RESET) {
                return ResponseEntity.ok(new ResponseMessage("If an account exists with this email, we've sent a new OTP."));
            }
            return ResponseEntity.badRequest().body(new ResponseMessage("User not found."));
        }

        if (otpType == OtpType.EMAIL_VERIFICATION) {
            if (Boolean.TRUE.equals(user.getEmailVerified())) {
                return ResponseEntity.ok(new ResponseMessage("Email is already verified."));
            }
            otpService.sendVerificationOtp(user, httpRequest);
        } else {
            // Only LOCAL users can reset password
            if (user.getProvider() != null && user.getProvider() != AuthProvider.LOCAL) {
                return ResponseEntity.ok(new ResponseMessage("If an account exists with this email, we've sent a new OTP."));
            }
            otpService.sendPasswordResetOtp(user, httpRequest);
        }

        return ResponseEntity.ok(new ResponseMessage("OTP sent successfully. Please check your email."));
    }

    // ──────────────────────────── Helpers ────────────────────────────

    /**
     * Creates Authentication object from User entity
     */
    private Authentication createAuthenticationFromUser(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        return new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
    }
}
