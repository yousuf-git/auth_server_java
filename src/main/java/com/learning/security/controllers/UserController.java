package com.learning.security.controllers;

import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SessionDTO;
import com.learning.security.enums.RevocationReason;
import com.learning.security.models.RefreshToken;
import com.learning.security.repos.RefreshTokenRepository;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Controller for user profile and session management operations
 */
@RestController
@RequestMapping("/api/user")
@CrossOrigin(originPatterns = "*", maxAge = 3600, allowCredentials = "true")
public class UserController {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        String email = authentication.getName();
        
        return userRepo.findByEmail(email)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ==================== Session Management ====================

    /**
     * Get all active sessions for the current user
     */
    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMySessions(Authentication authentication, HttpServletRequest request) {
        String email = authentication.getName();
        
        return userRepo.findByEmail(email)
                .map(user -> {
                    List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
                    String currentTokenHash = getCurrentTokenHash(request);
                    
                    List<SessionDTO> sessionDTOs = sessions.stream()
                            .map(token -> SessionDTO.fromRefreshToken(token, currentTokenHash))
                            .collect(Collectors.toList());
                    
                    return ResponseEntity.ok(sessionDTOs);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Revoke a specific session (logout from specific device)
     */
    @DeleteMapping("/sessions/{sessionId}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revokeSession(
            @PathVariable String sessionId,
            Authentication authentication,
            HttpServletResponse response,
            HttpServletRequest request) {
        
        String email = authentication.getName();
        
        return userRepo.findByEmail(email)
                .map(user -> {
                    // Verify the session belongs to this user
                    return refreshTokenRepository.findByIdAndUser(sessionId, user)
                            .map(token -> {
                                if (token.isRevoked()) {
                                    return ResponseEntity.badRequest()
                                            .body(new ResponseMessage("Session already revoked"));
                                }
                                
                                // Check if revoking current session
                                String currentTokenHash = getCurrentTokenHash(request);
                                boolean isCurrentSession = token.getTokenHash().equals(currentTokenHash);
                                
                                token.revoke(RevocationReason.MANUAL_LOGOUT);
                                refreshTokenRepository.save(token);
                                
                                // If revoking current session, clear the cookie
                                if (isCurrentSession) {
                                    clearRefreshTokenCookie(response);
                                }
                                
                                return ResponseEntity.ok(new ResponseMessage("Session revoked successfully"));
                            })
                            .orElse(ResponseEntity.notFound().build());
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Revoke all other sessions (keep current session active)
     */
    @DeleteMapping("/sessions/other")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> revokeOtherSessions(Authentication authentication, HttpServletRequest request) {
        String email = authentication.getName();
        
        return userRepo.findByEmail(email)
                .map(user -> {
                    String currentTokenHash = getCurrentTokenHash(request);
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

    // ========== Helper Methods ==========

    /**
     * Get current refresh token hash from cookie
     */
    private String getCurrentTokenHash(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return hashToken(cookie.getValue());
                }
            }
        }
        return null;
    }

    /**
     * Hash token using SHA-256 (same as RefreshTokenService)
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    /**
     * Clear refresh token cookie
     */
    private void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set to true in production
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
