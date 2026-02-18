package com.learning.security.controllers;

import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SessionDTO;
import com.learning.security.dtos.UserDTO;
import com.learning.security.dtos.admin.*;
import com.learning.security.enums.RevocationReason;
import com.learning.security.models.Permission;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.repos.RefreshTokenRepository;
import com.learning.security.services.PermissionService;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.RoleService;
import com.learning.security.services.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Controller for Admin operations - full user, role, and permission management
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasAuthority('ROLE_SUPER_ADMIN')")
@Validated
public class AdminController {

    @Autowired
    private UserService userService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private RefreshTokenService refreshTokenService;

    // ==================== User Management ====================

    @GetMapping("/users")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<UserDTO> users = userService.findAll().stream()
                .map(UserDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUserById(@PathVariable @Positive Integer id) {
        return userService.findById(id)
                .map(user -> ResponseEntity.ok(UserDTO.fromEntity(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@Valid @RequestBody CreateUserRequest request) {
        if (userService.existsByEmail(request.getEmail())) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Email already exists"));
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setPhone(request.getPhone());
        user.setCnic(request.getCnic());
        user.setCountry(request.getCountry());
        user.setCity(request.getCity());
        user.setProvince(request.getProvince());
        user.setArea(request.getArea());
        user.setAddress(request.getAddress());
        user.setIsLocked(request.getIsLocked() != null ? request.getIsLocked() : false);

        if (request.getRoleId() != null) {
            roleService.findById(request.getRoleId()).ifPresent(user::setRole);
        }

        User savedUser = userService.save(user);
        return new ResponseEntity<>(UserDTO.fromEntity(savedUser), HttpStatus.CREATED);
    }

    @PutMapping("/users/{id}")
    public ResponseEntity<?> updateUser(@PathVariable @Positive Integer id,
                                        @Valid @RequestBody UpdateUserRequest request) {
        return userService.findById(id)
                .map(user -> {
                    if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
                        if (userService.existsByEmail(request.getEmail())) {
                            return ResponseEntity.badRequest().body(new ResponseMessage("Email already exists"));
                        }
                        user.setEmail(request.getEmail());
                    }

                    if (request.getPassword() != null && !request.getPassword().isEmpty()) {
                        user.setPassword(passwordEncoder.encode(request.getPassword()));
                    }

                    if (request.getPhone() != null) {
                        user.setPhone(request.getPhone());
                    }

                    if (request.getFirstName() != null) {
                        user.setFirstName(request.getFirstName());
                    }

                    if (request.getLastName() != null) {
                        user.setLastName(request.getLastName());
                    }

                    if (request.getCnic() != null) {
                        user.setCnic(request.getCnic());
                    }

                    if (request.getCountry() != null) {
                        user.setCountry(request.getCountry());
                    }

                    if (request.getCity() != null) {
                        user.setCity(request.getCity());
                    }

                    if (request.getProvince() != null) {
                        user.setProvince(request.getProvince());
                    }

                    if (request.getArea() != null) {
                        user.setArea(request.getArea());
                    }

                    if (request.getAddress() != null) {
                        user.setAddress(request.getAddress());
                    }

                    if (request.getIsLocked() != null) {
                        user.setIsLocked(request.getIsLocked());
                    }

                    if (request.getRoleId() != null) {
                        roleService.findById(request.getRoleId()).ifPresent(user::setRole);
                    }

                    User savedUser = userService.save(user);
                    return ResponseEntity.ok(UserDTO.fromEntity(savedUser));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable @Positive Integer id) {
        if (userService.existsById(id)) {
            userService.deleteById(id);
            return ResponseEntity.ok(new ResponseMessage("User deleted successfully"));
        }
        return ResponseEntity.notFound().build();
    }

    // ==================== Role Management ====================

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleService.findAll());
    }

    @GetMapping("/roles/{id}")
    public ResponseEntity<?> getRoleById(@PathVariable @Positive Integer id) {
        return roleService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/roles")
    public ResponseEntity<?> createRole(@Valid @RequestBody CreateRoleRequest request) {
        if (roleService.existsByName(request.getName())) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Role with this name already exists"));
        }

        Role role = Role.builder()
                .name(request.getName())
                .description(request.getDescription())
                .permissions(new HashSet<>())
                .build();

        if (request.getPermissionIds() != null) {
            Set<Permission> permissions = new HashSet<>();
            for (Integer permId : request.getPermissionIds()) {
                permissionService.findById(permId).ifPresent(permissions::add);
            }
            role.setPermissions(permissions);
        }

        Role savedRole = roleService.save(role);
        return new ResponseEntity<>(savedRole, HttpStatus.CREATED);
    }

    @PutMapping("/roles/{id}")
    public ResponseEntity<?> updateRole(@PathVariable @Positive Integer id,
                                        @Valid @RequestBody UpdateRoleRequest request) {
        return roleService.findById(id)
                .map(role -> {
                    if (request.getName() != null && !request.getName().equals(role.getName())) {
                        if (roleService.existsByName(request.getName())) {
                            return ResponseEntity.badRequest().body(new ResponseMessage("Role name already exists"));
                        }
                        role.setName(request.getName());
                    }

                    if (request.getDescription() != null) {
                        role.setDescription(request.getDescription());
                    }

                    if (request.getPermissionIds() != null) {
                        Set<Permission> permissions = new HashSet<>();
                        for (Integer permId : request.getPermissionIds()) {
                            permissionService.findById(permId).ifPresent(permissions::add);
                        }
                        role.setPermissions(permissions);
                    }

                    if (request.getIsActive() != null) {
                        role.setIsActive(request.getIsActive());
                    }

                    Role savedRole = roleService.save(role);
                    return ResponseEntity.ok(savedRole);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/roles/{id}")
    public ResponseEntity<?> deleteRole(@PathVariable @Positive Integer id) {
        if (roleService.existsById(id)) {
            long userCount = userService.countByRoleId(id);

            if (userCount > 0) {
                return ResponseEntity.badRequest()
                        .body(new ResponseMessage("Cannot delete role: " + userCount + " users are assigned to this role"));
            }

            roleService.deleteById(id);
            return ResponseEntity.ok(new ResponseMessage("Role deleted successfully"));
        }
        return ResponseEntity.notFound().build();
    }

    // ==================== Permission Management ====================

    @GetMapping("/permissions")
    public ResponseEntity<List<Permission>> getAllPermissions() {
        return ResponseEntity.ok(permissionService.findAll());
    }

    @GetMapping("/permissions/{id}")
    public ResponseEntity<?> getPermissionById(@PathVariable @Positive Integer id) {
        return permissionService.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/permissions")
    public ResponseEntity<?> createPermission(@Valid @RequestBody CreatePermissionRequest request) {
        if (permissionService.existsByName(request.getName())) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Permission already exists"));
        }

        Permission permission = Permission.builder()
                .name(request.getName())
                .description(request.getDescription())
                .build();

        Permission savedPermission = permissionService.save(permission);
        return new ResponseEntity<>(savedPermission, HttpStatus.CREATED);
    }

    @DeleteMapping("/permissions/{id}")
    public ResponseEntity<?> deletePermission(@PathVariable @Positive Integer id) {
        if (permissionService.existsById(id)) {
            permissionService.deleteById(id);
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
        List<RefreshToken> allSessions = refreshTokenRepository.findAllActiveSessions(Instant.now());
        List<SessionDTO> sessionDTOs = allSessions.stream()
                .map(SessionDTO::fromRefreshTokenForAdmin)
                .collect(Collectors.toList());
        return ResponseEntity.ok(sessionDTOs);
    }

    /**
     * Get all active sessions for a specific user
     */
    @GetMapping("/users/{userId}/sessions")
    public ResponseEntity<?> getUserSessions(@PathVariable @Positive Integer userId) {
        return userService.findById(userId)
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
    public ResponseEntity<?> revokeAllUserSessions(@PathVariable @Positive Integer userId) {
        if (!userService.existsById(userId)) {
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
        Instant now = Instant.now();
        long totalActiveSessions = refreshTokenRepository.countAllActiveSessions(now);
        long usersWithActiveSessions = refreshTokenRepository.countUsersWithActiveSessions(now);
        long totalUsers = userService.count();

        Map<String, Object> stats = new HashMap<>();
        stats.put("totalActiveSessions", totalActiveSessions);
        stats.put("usersWithActiveSessions", usersWithActiveSessions);
        stats.put("totalUsers", totalUsers);

        return ResponseEntity.ok(stats);
    }
}
