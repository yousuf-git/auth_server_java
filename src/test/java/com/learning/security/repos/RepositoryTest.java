package com.learning.security.repos;

import com.learning.security.models.Role;
import com.learning.security.models.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for UserRepo and RoleRepo
 * Tests database operations with in-memory H2 database
 */
@DataJpaTest
class RepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private RoleRepo roleRepo;

    private Role userRole;
    private Role adminRole;
    private Role modRole;

    @BeforeEach
    void setUp() {
        // Setup roles - using Role.of() factory method
        userRole = Role.of("ROLE_USER");
        userRole = entityManager.persistAndFlush(userRole);
        entityManager.clear();

        adminRole = Role.of("ROLE_ADMIN");
        adminRole = entityManager.persistAndFlush(adminRole);
        entityManager.clear();

        modRole = Role.of("ROLE_MODERATOR");
        modRole = entityManager.persistAndFlush(modRole);
        entityManager.clear();
    }

    // UserRepo Tests

    @Test
    void testFindByEmail_UserExists() {
        // Given
        createAndSaveUser("test@example.com", userRole);

        // When
        Optional<User> found = userRepo.findByEmail("test@example.com");

        // Then
        assertTrue(found.isPresent());
        assertEquals("test@example.com", found.get().getEmail());
    }

    @Test
    void testFindByEmail_UserNotExists() {
        // When
        Optional<User> found = userRepo.findByEmail("nonexistent@example.com");

        // Then
        assertFalse(found.isPresent());
    }

    @Test
    void testExistsByEmail_EmailExists() {
        // Given
        createAndSaveUser("test@example.com", userRole);

        // When
        Boolean exists = userRepo.existsByEmail("test@example.com");

        // Then
        assertTrue(exists);
    }

    @Test
    void testExistsByEmail_EmailNotExists() {
        // When
        Boolean exists = userRepo.existsByEmail("nonexistent@example.com");

        // Then
        assertFalse(exists);
    }

    @Test
    void testSaveUser_Success() {
        // Given
        User user = new User();
        user.setFirstName("New");
        user.setLastName("User");
        user.setEmail("new@example.com");
        user.setPassword("password123");
        user.setRole(userRole);

        // When
        User saved = userRepo.save(user);

        // Then
        assertNotNull(saved.getId());
        assertEquals("new@example.com", saved.getEmail());
        assertNotNull(saved.getCreatedAt());
    }

    @Test
    void testSaveUser_WithAdminRole() {
        // Given
        User user = new User();
        user.setFirstName("Admin");
        user.setLastName("User");
        user.setEmail("admin@example.com");
        user.setPassword("password123");
        user.setRole(adminRole);

        // When
        User saved = userRepo.save(user);
        entityManager.flush();
        entityManager.clear();

        // Then
        User found = userRepo.findById(saved.getId()).get();
        assertNotNull(found.getRole());
        assertEquals("ROLE_ADMIN", found.getRole().getName());
    }

    @Test
    void testUpdateUser() {
        // Given
        User user = createAndSaveUser("original@example.com", userRole);
        Integer userId = user.getId();

        // When
        user.setEmail("updated@example.com");
        userRepo.save(user);
        entityManager.flush();
        entityManager.clear();

        // Then
        User found = userRepo.findById(userId).get();
        assertEquals("updated@example.com", found.getEmail());
    }

    @Test
    void testDeleteUser() {
        // Given
        User user = createAndSaveUser("delete@example.com", userRole);
        Integer userId = user.getId();

        // When
        userRepo.delete(user);
        entityManager.flush();

        // Then
        Optional<User> found = userRepo.findById(userId);
        assertFalse(found.isPresent());
    }

    @Test
    void testFindAllUsers() {
        // Given
        createAndSaveUser("user1@example.com", userRole);
        createAndSaveUser("user2@example.com", userRole);
        createAndSaveUser("user3@example.com", adminRole);

        // When
        List<User> users = userRepo.findAll();

        // Then
        assertTrue(users.size() >= 3);
    }

    @Test
    void testUserUniqueConstraints_Email() {
        // Given
        createAndSaveUser("unique@example.com", userRole);

        // When & Then - Attempting to save user with duplicate email should fail
        User duplicateUser = new User();
        duplicateUser.setFirstName("Dup");
        duplicateUser.setLastName("User");
        duplicateUser.setEmail("unique@example.com");
        duplicateUser.setPassword("password123");
        duplicateUser.setRole(userRole);

        assertThrows(Exception.class, () -> {
            userRepo.save(duplicateUser);
            entityManager.flush();
        });
    }

    // RoleRepo Tests

    @Test
    void testFindByName_RoleUser() {
        // When
        Optional<Role> found = roleRepo.findByName("ROLE_USER");

        // Then
        assertTrue(found.isPresent());
        assertEquals("ROLE_USER", found.get().getName());
    }

    @Test
    void testFindByName_RoleAdmin() {
        // When
        Optional<Role> found = roleRepo.findByName("ROLE_ADMIN");

        // Then
        assertTrue(found.isPresent());
        assertEquals("ROLE_ADMIN", found.get().getName());
    }

    @Test
    void testFindByName_RoleModerator() {
        // When
        Optional<Role> found = roleRepo.findByName("ROLE_MODERATOR");

        // Then
        assertTrue(found.isPresent());
        assertEquals("ROLE_MODERATOR", found.get().getName());
    }

    @Test
    void testSaveRole() {
        // Given
        Role newRole = new Role();
        newRole.setName("ROLE_CUSTOM");

        // When
        Role saved = roleRepo.save(newRole);

        // Then
        assertNotNull(saved.getId());
        assertEquals("ROLE_CUSTOM", saved.getName());
    }

    @Test
    void testFindAllRoles() {
        // When
        List<Role> roles = roleRepo.findAll();

        // Then
        assertEquals(3, roles.size());
        assertTrue(roles.stream().anyMatch(r -> r.getName().equals("ROLE_USER")));
        assertTrue(roles.stream().anyMatch(r -> r.getName().equals("ROLE_ADMIN")));
        assertTrue(roles.stream().anyMatch(r -> r.getName().equals("ROLE_MODERATOR")));
    }

    @Test
    void testDeleteRole() {
        // Given
        Role tempRole = new Role();
        tempRole.setName("ROLE_TEMP");
        tempRole = entityManager.persist(tempRole);
        entityManager.flush();
        Integer roleId = tempRole.getId();

        // When
        roleRepo.delete(tempRole);
        entityManager.flush();

        // Then
        Optional<Role> found = roleRepo.findById(roleId);
        assertFalse(found.isPresent());
    }

    @Test
    void testUserRoleCascade() {
        // Given
        User user = new User();
        user.setFirstName("Cascade");
        user.setLastName("User");
        user.setEmail("cascade@example.com");
        user.setPassword("password123");
        user.setRole(userRole);

        // When
        User saved = userRepo.save(user);
        entityManager.flush();
        Integer userId = saved.getId();
        
        // Delete user
        userRepo.delete(saved);
        entityManager.flush();

        // Then
        Optional<User> foundUser = userRepo.findById(userId);
        assertFalse(foundUser.isPresent());
        
        // Roles should still exist (cascade delete doesn't affect roles)
        assertTrue(roleRepo.findByName("ROLE_USER").isPresent());
        assertTrue(roleRepo.findByName("ROLE_ADMIN").isPresent());
    }

    @Test
    void testUserCreatedAtAutoGenerated() {
        // Given
        User user = new User();
        user.setFirstName("Timestamp");
        user.setLastName("User");
        user.setEmail("timestamp@example.com");
        user.setPassword("password123");
        user.setRole(userRole);

        // When
        User saved = userRepo.save(user);
        entityManager.flush();

        // Then
        assertNotNull(saved.getCreatedAt());
    }

    // Helper method
    private User createAndSaveUser(String email, Role role) {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword("password123");
        user.setRole(role);
        User saved = userRepo.save(user);
        entityManager.flush();
        return saved;
    }
}
