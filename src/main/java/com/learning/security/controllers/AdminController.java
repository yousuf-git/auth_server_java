package com.learning.security.controllers;

import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SessionDTO;
import com.learning.security.enums.RevocationReason;
import com.learning.security.models.Permission;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.repos.PermissionRepo;
import com.learning.security.repos.RefreshTokenRepository;
import com.learning.security.repos.RoleRepo;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for Admin operations - full user, role, and permission management
 */
@RestController
@RequestMapping("/api/admin")
@CrossOrigin(origins = "*", maxAge = 3600)
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class AdminController {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private RoleRepo roleRepo;

    @Autowired
    private PermissionRepo permissionRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    // ==================== User Management ====================

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepo.findAll());
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Integer id) {
        return userRepo.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@RequestBody Map<String, Object> request) {
        String email = (String) request.get("email");
        String password = (String) request.get("password");
        Integer roleId = (Integer) request.get("roleId");

        if (userRepo.existsByEmail(email)) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Email already exists"));
        }

        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setPhone((String) request.get("phone"));
        user.setIsLocked((Boolean) request.getOrDefault("isLocked", false));

        if (roleId != null) {
            roleRepo.findById(roleId).ifPresent(user::setRole);
        }

        User savedUser = userRepo.save(user);
        return ResponseEntity.ok(savedUser);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable Integer id, @RequestBody Map<String, Object> request) {
        return userRepo.findById(id)
                .map(user -> {
                    String email = (String) request.get("email");
                    if (email != null && !email.equals(user.getEmail())) {
                        if (userRepo.existsByEmail(email)) {
                            return ResponseEntity.badRequest().body(new ResponseMessage("Email already exists"));
                        }
                        user.setEmail(email);
                    }

                    String password = (String) request.get("password");
                    if (password != null && !password.isEmpty()) {
                        user.setPassword(passwordEncoder.encode(password));
                    }

                    if (request.containsKey("phone")) {
                        user.setPhone((String) request.get("phone"));
                    }

                    if (request.containsKey("isLocked")) {
                        user.setIsLocked((Boolean) request.get("isLocked"));
                    }

                    Integer roleId = (Integer) request.get("roleId");
                    if (roleId != null) {
                        roleRepo.findById(roleId).ifPresent(user::setRole);
                    }

                    User savedUser = userRepo.save(user);
                    return ResponseEntity.ok(savedUser);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable Integer id) {
        if (userRepo.existsById(id)) {
            userRepo.deleteById(id);
            return ResponseEntity.ok(new ResponseMessage("User deleted successfully"));
        }
        return ResponseEntity.notFound().build();
    }

    // ==================== Role Management ====================

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleRepo.findAll());
    }

    @GetMapping("/roles/{id}")
    public ResponseEntity<?> getRoleById(@PathVariable Integer id) {
        return roleRepo.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@RequestBody Map<String, Object> request) {
        String name = (String) request.get("name");
        
        if (roleRepo.existsByName(name)) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Role already exists"));
        }

        Role role = Role.builder()
                .name(name)
                .description((String) request.get("description"))
                .permissions(new HashSet<>())
                .build();

        // Add permissions
        @SuppressWarnings("unchecked")
        List<Integer> permissionIds = (List<Integer>) request.get("permissionIds");
        if (permissionIds != null) {
            Set<Permission> permissions = new HashSet<>();
            for (Integer permId : permissionIds) {
                permissionRepo.findById(permId).ifPresent(permissions::add);
            }
            role.setPermissions(permissions);
        }

        Role savedRole = roleRepo.save(role);
        return ResponseEntity.ok(savedRole);
    }

    @PutMapping("/roles/{id}")
    public ResponseEntity<?> updateRole(@PathVariable Integer id, @RequestBody Map<String, Object> request) {
        return roleRepo.findById(id)
                .map(role -> {
                    String name = (String) request.get("name");
                    if (name != null && !name.equals(role.getName())) {
                        if (roleRepo.existsByName(name)) {
                            return ResponseEntity.badRequest().body(new ResponseMessage("Role name already exists"));
                        }
                        role.setName(name);
                    }

                    if (request.containsKey("description")) {
                        role.setDescription((String) request.get("description"));
                    }

                    // Update permissions
                    @SuppressWarnings("unchecked")
                    List<Integer> permissionIds = (List<Integer>) request.get("permissionIds");
                    if (permissionIds != null) {
                        Set<Permission> permissions = new HashSet<>();
                        for (Integer permId : permissionIds) {
                            permissionRepo.findById(permId).ifPresent(permissions::add);
                        }
                        role.setPermissions(permissions);
                    }

                    Role savedRole = roleRepo.save(role);
                    return ResponseEntity.ok(savedRole);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/roles/{id}")
    public ResponseEntity<?> deleteRole(@PathVariable Integer id) {
        if (roleRepo.existsById(id)) {
            // Check if any users have this role
            long userCount = userRepo.findAll().stream()
                    .filter(u -> u.getRole() != null && u.getRole().getId().equals(id))
                    .count();
            
            if (userCount > 0) {
                return ResponseEntity.badRequest()
                        .body(new ResponseMessage("Cannot delete role: " + userCount + " users are assigned to this role"));
            }
            
            roleRepo.deleteById(id);
            return ResponseEntity.ok(new ResponseMessage("Role deleted successfully"));
        }
        return ResponseEntity.notFound().build();
    }

    // ==================== Permission Management ====================

    @GetMapping("/permissions")
    public ResponseEntity<List<Permission>> getAllPermissions() {
        return ResponseEntity.ok(permissionRepo.findAll());
    }

    @GetMapping("/permissions/{id}")
    public ResponseEntity<?> getPermissionById(@PathVariable Integer id) {
        return permissionRepo.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/permissions")
    public ResponseEntity<?> createPermission(@RequestBody Map<String, String> request) {
        String name = request.get("name");
        
        if (permissionRepo.existsByName(name)) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Permission already exists"));
        }

        Permission permission = Permission.builder()
                .name(name)
                .description(request.get("description"))
                .build();

        Permission savedPermission = permissionRepo.save(permission);
        return ResponseEntity.ok(savedPermission);
    }

    @DeleteMapping("/permissions/{id}")
    public ResponseEntity<?> deletePermission(@PathVariable Integer id) {
        if (permissionRepo.existsById(id)) {
            permissionRepo.deleteById(id);
            return ResponseEntity.ok(new ResponseMessage("Permission deleted successfully"));
        }
        return ResponseEntity.notFound().build();
    }

    // ==================== Session Management ====================

    /**
     * Get all active sessions across all users
     */
    @GetMapping("/sessions")
    public ResponseEntity<List<SessionDTO>> getAllActiveSessions() {
        List<User> allUsers = userRepo.findAll();
        List<SessionDTO> allSessions = new ArrayList<>();
        
        for (User user : allUsers) {
            List<RefreshToken> userSessions = refreshTokenService.getActiveUserSessions(user);
            allSessions.addAll(
                userSessions.stream()
                    .map(SessionDTO::fromRefreshTokenForAdmin)
                    .collect(Collectors.toList())
            );
        }
        
        // Sort by lastUsedAt descending (most recent first)
        allSessions.sort((a, b) -> {
            if (a.getLastUsedAt() == null && b.getLastUsedAt() == null) return 0;
            if (a.getLastUsedAt() == null) return 1;
            if (b.getLastUsedAt() == null) return -1;
            return b.getLastUsedAt().compareTo(a.getLastUsedAt());
        });
        
        return ResponseEntity.ok(allSessions);
    }

    /**
     * Get all active sessions for a specific user
     */
    @GetMapping("/users/{userId}/sessions")
    public ResponseEntity<?> getUserSessions(@PathVariable Integer userId) {
        return userRepo.findById(userId)
                .map(user -> {
                    List<RefreshToken> sessions = refreshTokenService.getActiveUserSessions(user);
                    List<SessionDTO> sessionDTOs = sessions.stream()
                            .map(SessionDTO::fromRefreshTokenForAdmin)
                            .collect(Collectors.toList());
                    return ResponseEntity.ok(sessionDTOs);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Revoke a specific session
     */
    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<?> revokeSession(@PathVariable String sessionId) {
        return refreshTokenRepository.findById(sessionId)
                .map(token -> {
                    if (token.isRevoked()) {
                        return ResponseEntity.badRequest()
                                .body(new ResponseMessage("Session already revoked"));
                    }
                    token.revoke(RevocationReason.ADMIN_REVOKED);
                    refreshTokenRepository.save(token);
                    return ResponseEntity.ok(new ResponseMessage("Session revoked successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Revoke all sessions for a specific user
     */
    @DeleteMapping("/users/{userId}/sessions")
    public ResponseEntity<?> revokeAllUserSessions(@PathVariable Integer userId) {
        if (!userRepo.existsById(userId)) {
            return ResponseEntity.notFound().build();
        }
        refreshTokenService.revokeAllUserTokens(userId, RevocationReason.ADMIN_REVOKED);
        return ResponseEntity.ok(new ResponseMessage("All sessions revoked for user"));
    }

    /**
     * Get session statistics
     */
    @GetMapping("/sessions/stats")
    public ResponseEntity<Map<String, Object>> getSessionStats() {
        List<User> allUsers = userRepo.findAll();
        long totalActiveSessions = 0;
        int usersWithActiveSessions = 0;
        
        for (User user : allUsers) {
            long userSessions = refreshTokenRepository.countActiveSessionsByUserId(user.getId(), Instant.now());
            totalActiveSessions += userSessions;
            if (userSessions > 0) {
                usersWithActiveSessions++;
            }
        }
        
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalActiveSessions", totalActiveSessions);
        stats.put("usersWithActiveSessions", usersWithActiveSessions);
        stats.put("totalUsers", allUsers.size());
        
        return ResponseEntity.ok(stats);
    }
}
