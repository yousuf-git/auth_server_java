package com.learning.security.utils;

import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.services.UserDetailsImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtUtilsTest {

    @InjectMocks
    private JwtUtils jwtUtils;

    @BeforeEach
    void setUp() {
        String testSecret = Base64.getEncoder().encodeToString(
            "MySecretKeyForJWTTestingPurpose12345678901234567890".getBytes()
        );
        int testExpirationTime = 3600000; // 1 hour in milliseconds

        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", testSecret);
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationTimeInMs", testExpirationTime);
    }

    @Test
    void testGenerateTokenByAuth_WithValidAuthentication() {
        Role role = new Role();
        role.setId(1);
        role.setName("ROLE_USER");
        
        User user = new User();
        user.setId(1);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(role);
        
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        String token = jwtUtils.generateTokenByAuth(authentication);

        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(jwtUtils.validateJwt(token));
    }

    @Test
    void testGetUsernameFromJwtToken_ReturnsCorrectEmail() {
        String email = "test@example.com";
        Role role = new Role();
        role.setId(2);
        role.setName("ROLE_USER");
        
        User user = new User();
        user.setId(2);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail(email);
        user.setPassword("encodedPassword");
        user.setRole(role);
        
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        String token = jwtUtils.generateTokenByAuth(authentication);

        String extractedEmail = jwtUtils.getUsernameFromJwtToken(token);

        assertEquals(email, extractedEmail);
    }

    @Test
    void testValidateJwt_WithValidToken_ReturnsTrue() {
        Role role = new Role();
        role.setId(3);
        role.setName("ROLE_USER");
        
        User user = new User();
        user.setId(3);
        user.setFirstName("Test");
        user.setLastName("User");
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(role);
        
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        String token = jwtUtils.generateTokenByAuth(authentication);

        boolean isValid = jwtUtils.validateJwt(token);

        assertTrue(isValid);
    }

    @Test
    void testValidateJwt_WithInvalidToken_ThrowsException() {
        String invalidToken = "invalid.jwt.token";

        assertThrows(com.learning.security.exceptions.CustomJwtException.class,
                () -> jwtUtils.validateJwt(invalidToken));
    }
}
