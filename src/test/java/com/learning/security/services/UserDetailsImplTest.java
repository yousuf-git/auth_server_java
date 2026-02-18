package com.learning.security.services;

import com.learning.security.models.Role;
import com.learning.security.models.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for UserDetailsImpl
 * Tests user details creation and Spring Security interface methods
 */
class UserDetailsImplTest {

    @Test
    void testBuildFromUser_WithRole() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertNotNull(userDetails);
        assertEquals(1, userDetails.getId());
        assertEquals("test@example.com", userDetails.getUsername()); // username is email
        assertEquals("test@example.com", userDetails.getEmail());
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.isActive());
        assertEquals(1, userDetails.getRoles().size());
        assertEquals("ROLE_USER", userDetails.getRoles().get(0).getAuthority());
    }

    @Test
    void testBuildFromUser_AdminRole() {
        // Given
        Role role = Role.builder().id(2).name("ROLE_ADMIN").build();
        User user = createUser("admin@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertNotNull(userDetails);
        assertEquals(1, userDetails.getRoles().size());
        
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        assertTrue(authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void testGetAuthorities() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

        // Then
        assertNotNull(authorities);
        assertEquals(1, authorities.size());
        assertTrue(authorities.stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void testGetUsername() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("username@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        String username = userDetails.getUsername();

        // Then - username should be email
        assertEquals("username@example.com", username);
    }

    @Test
    void testGetPassword() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertEquals("encodedPassword", userDetails.getPassword());
    }

    @Test
    void testIsAccountNonExpired() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When & Then
        assertTrue(userDetails.isAccountNonExpired());
    }

    @Test
    void testIsAccountNonLocked() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        user.setIsLocked(false);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When & Then
        assertTrue(userDetails.isAccountNonLocked());
    }

    @Test
    void testIsAccountLocked() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        user.setIsLocked(true);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When & Then
        assertFalse(userDetails.isAccountNonLocked());
    }

    @Test
    void testIsCredentialsNonExpired() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When & Then
        assertTrue(userDetails.isCredentialsNonExpired());
    }

    @Test
    void testIsEnabled() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // When & Then
        assertTrue(userDetails.isEnabled());
    }

    @Test
    void testGetEmail() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertEquals("test@example.com", userDetails.getEmail());
    }

    @Test
    void testGetName() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then - getName should return email
        assertEquals("test@example.com", userDetails.getName());
    }

    @Test
    void testIsActive() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertTrue(userDetails.isActive());
    }

    @Test
    void testGetRoles() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertNotNull(userDetails.getRoles());
        assertEquals(1, userDetails.getRoles().size());
        assertEquals("ROLE_USER", userDetails.getRoles().get(0).getAuthority());
    }

    @Test
    void testBuildFromUserWithNullUsername() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser(null, role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        assertNotNull(userDetails);
        assertNull(userDetails.getUsername());
    }

    @Test
    void testEqualsAndHashCode() {
        // Given
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser("test@example.com", role);
        
        UserDetailsImpl userDetails1 = UserDetailsImpl.build(user);
        UserDetailsImpl userDetails2 = UserDetailsImpl.build(user);

        // When & Then (Lombok generates equals and hashCode)
        assertEquals(userDetails1, userDetails2);
        assertEquals(userDetails1.hashCode(), userDetails2.hashCode());
    }

    @Test
    void testRoleConversionToGrantedAuthority() {
        // Given
        Role role = Role.builder().id(2).name("ROLE_ADMIN").build();
        User user = createUser("test@example.com", role);

        // When
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);

        // Then
        Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
        assertEquals(1, authorities.size());
        
        // Verify that role is converted to SimpleGrantedAuthority
        authorities.forEach(authority -> {
            assertTrue(authority.getAuthority().startsWith("ROLE_"));
        });
    }

    // Helper method
    private User createUser(String email, Role role) {
        User user = new User();
        user.setId(1);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword("encodedPassword");
        user.setRole(role);
        return user;
    }
}
