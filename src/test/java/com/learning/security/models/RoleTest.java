package com.learning.security.models;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Role entity
 * Tests string-based role names and entity behavior
 */
class RoleTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void testCreateValidRole() {
        // Given
        Role role = new Role();
        role.setId(1);
        role.setName("ROLE_USER");

        // When
        Set<ConstraintViolation<Role>> violations = validator.validate(role);

        // Then
        assertTrue(violations.isEmpty(), "Valid role should not have validation violations");
        assertEquals(1, role.getId());
        assertEquals("ROLE_USER", role.getName());
    }

    @Test
    void testRoleWithAdminName() {
        // Given
        Role role = new Role();
        role.setId(2);
        role.setName("ROLE_ADMIN");

        // When & Then
        assertEquals("ROLE_ADMIN", role.getName());
    }

    @Test
    void testRoleWithModeratorName() {
        // Given
        Role role = new Role();
        role.setId(3);
        role.setName("ROLE_MODERATOR");

        // When & Then
        assertEquals("ROLE_MODERATOR", role.getName());
    }

    @Test
    void testRoleWithCustomName() {
        // Given
        Role role = new Role();
        role.setId(4);
        role.setName("ROLE_SUPERVISOR");

        // When & Then
        assertEquals("ROLE_SUPERVISOR", role.getName());
    }

    @Test
    void testAllArgsConstructor() {
        // When
        Role role = Role.builder()
                .id(1)
                .name("ROLE_USER")
                .build();

        // Then
        assertEquals(1, role.getId());
        assertEquals("ROLE_USER", role.getName());
    }

    @Test
    void testRequiredArgsConstructor() {
        // When
        Role role = new Role("ROLE_ADMIN");

        // Then
        assertNull(role.getId());
        assertEquals("ROLE_ADMIN", role.getName());
    }

    @Test
    void testNoArgsConstructor() {
        // When
        Role role = new Role();

        // Then
        assertNull(role.getId());
        assertNull(role.getName());
    }

    @Test
    void testRoleBuilder() {
        // When
        Role role = Role.builder()
                .id(5)
                .name("ROLE_USER")
                .build();

        // Then
        assertEquals(5, role.getId());
        assertEquals("ROLE_USER", role.getName());
    }

    @Test
    void testStaticOfMethod() {
        // When
        Role role = Role.of("ROLE_MODERATOR");

        // Then
        assertNull(role.getId());
        assertEquals("ROLE_MODERATOR", role.getName());
    }

    @Test
    void testSettersAndGetters() {
        // Given
        Role role = new Role();

        // When
        role.setId(10);
        role.setName("ROLE_ADMIN");

        // Then
        assertEquals(10, role.getId());
        assertEquals("ROLE_ADMIN", role.getName());
    }

    @Test
    void testRoleEqualsAndHashCode() {
        // Given
        Role role1 = Role.builder().id(1).name("ROLE_USER").build();
        Role role2 = Role.builder().id(1).name("ROLE_USER").build();
        Role role3 = Role.builder().id(2).name("ROLE_ADMIN").build();

        // When & Then (Lombok generates equals and hashCode)
        assertEquals(role1, role2, "Roles with same data should be equal");
        assertEquals(role1.hashCode(), role2.hashCode(), "Hash codes should match");
        assertNotEquals(role1, role3, "Roles with different data should not be equal");
    }

    @Test
    void testRoleNameCanBeAnyString() {
        // Given
        Role customRole = Role.builder()
                .id(100)
                .name("ROLE_PLANT_MANAGER")
                .build();

        // When & Then
        assertEquals("ROLE_PLANT_MANAGER", customRole.getName());
        
        // Test another custom name
        customRole.setName("ROLE_CUSTOM_SUPERVISOR");
        assertEquals("ROLE_CUSTOM_SUPERVISOR", customRole.getName());
    }

    @Test
    void testRoleNameValidation() {
        // Given
        Role role = new Role();
        role.setId(1);
        role.setName("");

        // When
        Set<ConstraintViolation<Role>> violations = validator.validate(role);

        // Then
        assertFalse(violations.isEmpty(), "Empty role name should cause validation error");
    }

    @Test
    void testRoleNameNull() {
        // Given
        Role role = new Role();
        role.setId(1);
        role.setName(null);

        // When
        Set<ConstraintViolation<Role>> violations = validator.validate(role);

        // Then
        assertFalse(violations.isEmpty(), "Null role name should cause validation error");
    }
}
