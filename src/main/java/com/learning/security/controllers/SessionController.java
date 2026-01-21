package com.learning.security.controllers;

import com.learning.security.enums.RevocationReason;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.User;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * <h2>SessionController</h2>
 * <p>
 * REST API for session management
 * Allows admins to view and revoke user sessions
 * Allows users to view their own sessions
 * </p>
 */
@RestController
@RequestMapping("/api/sessions")
@CrossOrigin(origins = "*", maxAge = 3600)
public class SessionController {

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserRepo userRepo;

    /**
     * Get current user's active sessions
     * 
     * @param authentication Current authenticated user
     * @return List of active sessions with details
     */
    @GetMapping("/my")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<RefreshToken>> getMyActiveSessions(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        User user = userRepo.findById(userDetails.getId())
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
        return ResponseEntity.ok(sessions);
    }

    /**
     * Get all active sessions for a specific user (Admin only)
     * 
     * @param userId User ID to query sessions for
     * @return List of active sessions
     */
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<RefreshToken>> getUserSessions(@PathVariable Integer userId) {
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
        return ResponseEntity.ok(sessions);
    }

    /**
     * Revoke a specific session by session ID (Admin only)
     * 
     * @param sessionId Session ID (refresh token UUID) to revoke
     * @return Success message
     */
    @DeleteMapping("/{sessionId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> revokeSession(@PathVariable String sessionId, Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        User user = userRepo.findById(userDetails.getId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        refreshTokenService.revokeSession(sessionId, user);
        return ResponseEntity.ok("Session revoked successfully");
    }

    /**
     * Revoke all sessions for a specific user (Admin only)
     * 
     * @param userId User ID to revoke all sessions for
     * @return Success message with count of revoked sessions
     */
    @DeleteMapping("/user/{userId}/all")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> revokeAllUserSessions(@PathVariable Integer userId) {
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        refreshTokenService.revokeAllUserTokens(userId, RevocationReason.ADMIN_REVOKED);
        return ResponseEntity.ok(String.format("Successfully revoked all sessions for user %s", 
                user.getEmail()));
    }

    /**
     * Get active session count for a user (Admin only)
     * 
     * @param userId User ID to count sessions for
     * @return Session count
     */
    @GetMapping("/user/{userId}/count")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Integer> getActiveSessionCount(@PathVariable Integer userId) {
        User user = userRepo.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));

        int count = refreshTokenService.getActiveUserSessions(user).size();
        return ResponseEntity.ok(count);
    }
}
