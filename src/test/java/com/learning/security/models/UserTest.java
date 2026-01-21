package com.learning.security.models;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void testCreateValidUser() {
        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("password123");
        
        Role userRole = new Role();
        userRole.setId(1);
        userRole.setName("ROLE_USER");
        user.setRole(userRole);

        Set<ConstraintViolation<User>> violations = validator.validate(user);

        assertTrue(violations.isEmpty());
        assertEquals("test@example.com", user.getEmail());
        assertEquals("ROLE_USER", user.getRole().getName());
    }

    @Test
    void testUserWithoutEmail_ValidationFails() {
        User user = new User();
        user.setPassword("password123");

        Set<ConstraintViolation<User>> violations = validator.validate(user);

        assertFalse(violations.isEmpty());
    }

    @Test
    void testUserWithRole() {
        Role role = new Role();
        role.setId(1);
        role.setName("ROLE_ADMIN");

        User user = new User();
        user.setEmail("test@example.com");
        user.setPassword("password123");
        user.setRole(role);

        assertEquals("ROLE_ADMIN", user.getRole().getName());
    }
}
