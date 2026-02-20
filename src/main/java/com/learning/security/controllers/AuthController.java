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

import java.util.LinkedHashMap;
import java.util.Map;

// @CrossOrigin(originPatterns = "*", maxAge = 3600, allowCredentials = "true") // Allow credentials for cookies, maxAge is in seconds; 3600s = 1 hr
/*
 * The HTTP Access-Control-Max-Age response header indicates how long the
 * results of a preflight request (that is, the information contained in the
 * Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be
 * cached.
 */
// https://docs.spring.io/spring-framework/docs/4.2.x/spring-framework-reference/html/cors.html

@RestController
@RequestMapping("/auth")
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

    // ──────────────────────────── Signup ────────────────────────────

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignUpRequest request,
                                    HttpServletRequest httpRequest) {

        if (userService.existsByEmail(request.getEmail())) {
            // Check if user exists but email not verified — allow resend
            User existingUser = userService.findByEmail(request.getEmail()).orElse(null);
            if (existingUser != null && Boolean.FALSE.equals(existingUser.getEmailVerified())) {
                // Resend verification OTP for existing unverified user
                try {
                    otpService.sendVerificationOtp(existingUser, httpRequest);
                } catch (OtpException e) {
                    return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                            .body(new ResponseMessage(e.getMessage()));
                }
                Map<String, Object> response = new LinkedHashMap<>();
                response.put("message", "A verification code has been sent to your email. Please verify to complete registration.");
                response.put("email", request.getEmail());
                response.put("otpExpiresInSeconds", 600);
                return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
            }
            return new ResponseEntity<>(new ResponseMessage("Email already registered."), HttpStatus.CONFLICT);
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setPhone(request.getPhone());
        user.setProvider(AuthProvider.LOCAL);
        user.setEmailVerified(false);

        // Flexible role assignment
        if (request.getRole() != null && !request.getRole().isBlank()) {
            Role role = roleService.findByName(request.getRole()).orElse(null);
            if (role == null) {
                return new ResponseEntity<>(new ResponseMessage("Role '" + request.getRole() + "' not found."),
                        HttpStatus.BAD_REQUEST);
            }
            user.setRole(role);
        } else {
            // Default role assignment
            Role defaultRole = roleService.findByName("ROLE_CUSTOMER").orElse(null);
            if (defaultRole == null) {
                return new ResponseEntity<>(new ResponseMessage("Default role 'ROLE_CUSTOMER' not found."),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            }
            user.setRole(defaultRole);
        }

        User savedUser = userService.save(user);

        // Send verification OTP
        try {
            otpService.sendVerificationOtp(savedUser, httpRequest);
        } catch (Exception e) {
            log.warn("Failed to send verification email to {}: {}", savedUser.getEmail(), e.getMessage());
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "Registration successful. A verification code has been sent to your email.");
        response.put("email", savedUser.getEmail());
        response.put("otpExpiresInSeconds", 600);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response);
    }

    // ──────────────────────────── Signin ────────────────────────────

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@Valid @RequestBody LoginRequest loginRequest,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        // Check if user exists
        User user = userService.findByEmail(loginRequest.getEmail()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid email or password."));
        }

        // Check if email is verified
        if (Boolean.FALSE.equals(user.getEmailVerified())) {
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", "Email not verified. Please verify your email before logging in.");
            response.put("email", user.getEmail());
            response.put("emailVerified", false);
            response.put("action", "VERIFY_EMAIL");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
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
            
            // Extract permissions as space-separated string
            String scopes = "";
            if (user.getRole() != null && user.getRole().getPermissions() != null) {
                scopes = user.getRole().getPermissions().stream()
                        .map(p -> p.getName())
                        .reduce((a, b) -> a + " " + b)
                        .orElse("");
            }

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                userDetails.getId(),
                userDetails.getEmail(),
                role,
                scopes,
                jwtUtils.getJwtExpirationMs(),
                user.getEmailVerified()
            );

            return ResponseEntity.ok(authResponse);

        } catch (LockedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ResponseMessage("Account is locked. Please contact administrator."));
        } catch (AuthenticationException e) {
            log.error("Failed login attempt for email {}: {}", loginRequest.getEmail(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid email or password."));
        }
    }

    // ──────────────────────────── Token Refresh ────────────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ResponseMessage("Refresh token not found."));
            }

            TokenPair tokenPair = refreshTokenService.rotateRefreshToken(refreshToken, request);

            cookieUtils.setRefreshTokenCookie(response, tokenPair.getRawToken());

            User user = tokenPair.getRefreshToken().getUser();
            Authentication authentication = createAuthenticationFromUser(user);
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            String role = user.getRole() != null ? user.getRole().getName() : "";
            
            // Extract permissions as space-separated string
            String scopes = "";
            if (user.getRole() != null && user.getRole().getPermissions() != null) {
                scopes = user.getRole().getPermissions().stream()
                        .map(p -> p.getName())
                        .reduce((a, b) -> a + " " + b)
                        .orElse("");
            }

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                user.getId(),
                user.getEmail(),
                role,
                scopes,
                jwtUtils.getJwtExpirationMs(),
                user.getEmailVerified()
            );

            return ResponseEntity.ok(authResponse);

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Session expired. Please login again."));
        }
    }

    // ──────────────────────────── Logout ────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken != null) {
                refreshTokenService.revokeRefreshToken(refreshToken, RevocationReason.MANUAL_LOGOUT);
            }

            cookieUtils.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(new ResponseMessage("Logged out successfully."));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.ok(new ResponseMessage("Logged out successfully."));
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

            return ResponseEntity.ok(new ResponseMessage("Logged out from all devices."));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid session."));
        }
    }

    // ──────────────────────────── Email Verification ────────────────────────────

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody VerifyEmailRequest request,
                                         HttpServletRequest httpRequest,
                                         HttpServletResponse httpResponse) {

        User user = userService.findByEmail(request.getEmail()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ResponseMessage("No account found with this email."));
        }

        if (Boolean.TRUE.equals(user.getEmailVerified())) {
            return ResponseEntity.ok(new ResponseMessage("Email is already verified. You can login."));
        }

        // Verify OTP (throws OtpException on failure — handled by GlobalExceptionHandler)
        otpService.verifyOtp(user.getEmail(), request.getOtp(), OtpType.EMAIL_VERIFICATION);

        // Mark email as verified
        user.setEmailVerified(true);
        userService.save(user);

        // Send welcome email (non-blocking)
        otpService.sendWelcomeEmail(user);

        // Auto-login: generate tokens so user doesn't have to login separately
        try {
            Authentication authentication = createAuthenticationFromUser(user);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            TokenPair tokenPair = refreshTokenService.createRefreshToken(user, httpRequest, null);
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            String role = user.getRole() != null ? user.getRole().getName() : "";
            
            // Extract permissions as space-separated string
            String scopes = "";
            if (user.getRole() != null && user.getRole().getPermissions() != null) {
                scopes = user.getRole().getPermissions().stream()
                        .map(p -> p.getName())
                        .reduce((a, b) -> a + " " + b)
                        .orElse("");
            }

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                user.getId(),
                user.getEmail(),
                role,
                scopes,
                jwtUtils.getJwtExpirationMs(),
                true
            );

            return ResponseEntity.ok(authResponse);

        } catch (Exception e) {
            log.warn("Email verified but token generation failed for {}: {}", user.getEmail(), e.getMessage());
            return ResponseEntity.ok(new ResponseMessage("Email verified successfully. Please login."));
        }
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
                return ResponseEntity.ok(new ResponseMessage("If an account exists with this email, a new OTP has been sent."));
            }
            return ResponseEntity.badRequest().body(new ResponseMessage("No account found with this email."));
        }

        if (otpType == OtpType.EMAIL_VERIFICATION) {
            if (Boolean.TRUE.equals(user.getEmailVerified())) {
                return ResponseEntity.ok(new ResponseMessage("Email is already verified."));
            }
            otpService.sendVerificationOtp(user, httpRequest);
        } else {
            // Only LOCAL users can reset password
            if (user.getProvider() != null && user.getProvider() != AuthProvider.LOCAL) {
                return ResponseEntity.ok(new ResponseMessage("If an account exists with this email, a new OTP has been sent."));
            }
            otpService.sendPasswordResetOtp(user, httpRequest);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("message", "OTP sent successfully. Please check your email.");
        response.put("otpExpiresInSeconds", 600);
        return ResponseEntity.ok(response);
    }

    // ──────────────────────────── Forgot Password ────────────────────────────

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request,
                                            HttpServletRequest httpRequest) {
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
            log.warn("Forgot-password rate limited for {}: {}", request.getEmail(), e.getMessage());
        } catch (Exception e) {
            log.error("Error in forgot-password for {}: {}", request.getEmail(), e.getMessage());
        }

        return ResponseEntity.ok(new ResponseMessage(genericMessage));
    }

    // ──────────────────────────── Reset Password ────────────────────────────

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        User user = userService.findByEmail(request.getEmail()).orElse(null);
        if (user == null) {
            throw new OtpException("Invalid email or OTP.");
        }

        // Verify OTP
        otpService.verifyOtp(user.getEmail(), request.getOtp(), OtpType.PASSWORD_RESET);

        // Update password
        user.setPassword(encoder.encode(request.getNewPassword()));
        userService.save(user);

        // Revoke all sessions for security (force re-login)
        refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.ADMIN_REVOKED);

        // Send notification email
        otpService.sendPasswordChangedNotification(user);

        return ResponseEntity.ok(new ResponseMessage("Password has been reset successfully. Please login with your new password."));
    }

    // ──────────────────────────── Helpers ────────────────────────────

    private Authentication createAuthenticationFromUser(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        return new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
    }
}
