package com.learning.security.services;

import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.repos.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserDetailsServiceImpl
 * Tests user loading functionality for Spring Security
 */
class UserDetailsServiceImplTest {

    @Mock
    private UserRepo userRepo;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testLoadUserByUsername_UserExists() {
        // Given
        String email = "test@example.com";
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser(email, role);
        
        when(userRepo.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        // Then
        assertNotNull(userDetails);
        assertEquals(email, userDetails.getUsername()); // username is email
        assertEquals("encodedPassword", userDetails.getPassword());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        
        verify(userRepo, times(1)).findByEmail(email);
    }

    @Test
    void testLoadUserByUsername_UserNotFound() {
        // Given
        String email = "nonexistent@example.com";
        when(userRepo.findByEmail(email)).thenReturn(Optional.empty());

        // When & Then
        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(email)
        );
        
        assertTrue(exception.getMessage().contains(email));
        verify(userRepo, times(1)).findByEmail(email);
    }

    @Test
    void testLoadUserByUsername_WithAdminRole() {
        // Given
        String email = "admin@example.com";
        Role role = Role.builder().id(2).name("ROLE_ADMIN").build();
        User user = createUser(email, role);
        
        when(userRepo.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        // Then
        assertNotNull(userDetails);
        assertEquals(1, userDetails.getAuthorities().size());
        assertTrue(userDetails.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
        
        verify(userRepo, times(1)).findByEmail(email);
    }

    @Test
    void testLoadUserByUsername_LockedAccount() {
        // Given
        String email = "locked@example.com";
        Role role = Role.builder().id(1).name("ROLE_USER").build();
        User user = createUser(email, role);
        user.setIsLocked(true);
        
        when(userRepo.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        // Then
        assertNotNull(userDetails);
        assertFalse(userDetails.isAccountNonLocked());
        verify(userRepo, times(1)).findByEmail(email);
    }

    @Test
    void testLoadUserByUsername_NullEmail() {
        // Given
        String email = null;
        when(userRepo.findByEmail(null)).thenReturn(Optional.empty());

        // When & Then
        assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(email));
        
        verify(userRepo, times(1)).findByEmail(null);
    }

    @Test
    void testLoadUserByUsername_EmptyEmail() {
        // Given
        String email = "";
        when(userRepo.findByEmail(email)).thenReturn(Optional.empty());

        // When & Then
        assertThrows(UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(email));
        
        verify(userRepo, times(1)).findByEmail(email);
    }

    // Helper method
    private User createUser(String email, Role role) {
        User user = new User();
        user.setId(1);
        user.setEmail(email);
        user.setPassword("encodedPassword");
        user.setRole(role);
        user.setIsLocked(false);
        return user;
    }
}
