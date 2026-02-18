package com.learning.security.controllers;

import com.learning.security.dtos.ChangePasswordRequest;
import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SessionDTO;
import com.learning.security.dtos.UserDTO;
import com.learning.security.enums.AuthProvider;
import com.learning.security.enums.RevocationReason;
import com.learning.security.exceptions.BadRequestException;
import com.learning.security.models.RefreshToken;
import com.learning.security.repos.RefreshTokenRepository;
import com.learning.security.services.OtpService;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserService;
import com.learning.security.utils.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private CookieUtils cookieUtils;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private OtpService otpService;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        String email = authentication.getName();

        return userService.findByEmail(email)
                .map(user -> ResponseEntity.ok(UserDTO.fromEntity(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMySessions(Authentication authentication, HttpServletRequest request) {
        String email = authentication.getName();

        return userService.findByEmail(email)
                .map(user -> {
                    List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
                    String currentTokenHash = cookieUtils.getCurrentTokenHash(request);

                    List<SessionDTO> sessionDTOs = sessions.stream()
                            .map(token -> SessionDTO.fromRefreshToken(token, currentTokenHash))
                            .collect(Collectors.toList());

                    return ResponseEntity.ok(sessionDTOs);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/sessions/{sessionId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revokeSession(
            @PathVariable String sessionId,
            Authentication authentication,
            HttpServletResponse response,
            HttpServletRequest request) {

        String email = authentication.getName();

        return userService.findByEmail(email)
                .map(user -> {
                    return refreshTokenRepository.findByIdAndUser(sessionId, user)
                            .map(token -> {
                                if (token.isRevoked()) {
                                    return ResponseEntity.badRequest()
                                            .body(new ResponseMessage("Session already revoked"));
                                }

                                String currentTokenHash = cookieUtils.getCurrentTokenHash(request);
                                boolean isCurrentSession = token.getTokenHash().equals(currentTokenHash);

                                token.revoke(RevocationReason.MANUAL_LOGOUT);
                                refreshTokenRepository.save(token);

                                if (isCurrentSession) {
                                    cookieUtils.clearRefreshTokenCookie(response);
                                }

                                return ResponseEntity.ok(new ResponseMessage("Session revoked successfully"));
                            })
                            .orElse(ResponseEntity.notFound().build());
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/sessions/other")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revokeOtherSessions(Authentication authentication, HttpServletRequest request) {
        String email = authentication.getName();

        return userService.findByEmail(email)
                .map(user -> {
                    String currentTokenHash = cookieUtils.getCurrentTokenHash(request);
                    List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);

                    int revokedCount = 0;
                    for (RefreshToken token : sessions) {
                        if (!token.getTokenHash().equals(currentTokenHash)) {
                            token.revoke(RevocationReason.MANUAL_LOGOUT);
                            refreshTokenRepository.save(token);
                            revokedCount++;
                        }
                    }

                    return ResponseEntity.ok(new ResponseMessage("Revoked " + revokedCount + " other session(s)"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    // ──────────────────────────── Change Password ────────────────────────────

    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> changePassword(@Valid @RequestBody ChangePasswordRequest request,
                                            Authentication authentication,
                                            HttpServletRequest httpRequest) {
        String email = authentication.getName();

        return userService.findByEmail(email)
                .map(user -> {
                    // OAuth users cannot change password this way
                    if (user.getProvider() != null && user.getProvider() != AuthProvider.LOCAL) {
                        throw new BadRequestException(
                                "Password cannot be changed for " + user.getProvider() + " accounts. " +
                                "Please manage your password through your " + user.getProvider() + " account.");
                    }

                    // Verify current password
                    if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
                        throw new BadRequestException("Current password is incorrect.");
                    }

                    // Prevent setting same password
                    if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
                        throw new BadRequestException("New password must be different from your current password.");
                    }

                    // Update password
                    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
                    userService.save(user);

                    // Revoke all other sessions (keep current session active)
                    String currentTokenHash = cookieUtils.getCurrentTokenHash(httpRequest);
                    List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
                    for (RefreshToken token : sessions) {
                        if (!token.getTokenHash().equals(currentTokenHash)) {
                            token.revoke(RevocationReason.ADMIN_REVOKED);
                            refreshTokenRepository.save(token);
                        }
                    }

                    // Send password changed notification
                    otpService.sendPasswordChangedNotification(user);

                    return ResponseEntity.ok(new ResponseMessage("Password changed successfully. All other sessions have been logged out."));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
