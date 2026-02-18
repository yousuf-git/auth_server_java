package com.learning.security.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.security.dtos.LoginRequest;
import com.learning.security.dtos.SignUpRequest;
import com.learning.security.dtos.TokenPair;
import com.learning.security.models.RefreshToken;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.RoleService;
import com.learning.security.services.UserService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.CookieUtils;
import com.learning.security.utils.JwtUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserService userService;

    @MockitoBean
    private RoleService roleService;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private JwtUtils jwtUtils;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private CookieUtils cookieUtils;

    private Role defaultRole;

    @BeforeEach
    void setUp() {
        defaultRole = new Role();
        defaultRole.setId(1);
        defaultRole.setName("ROLE_CUSTOMER");
    }

    @Test
    void testSignup_WithValidData_CreatesUser() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setFirstName("Test");
        signUpRequest.setLastName("User");
        signUpRequest.setEmail("test@example.com");
        signUpRequest.setPassword("password123");
        signUpRequest.setRole("ROLE_CUSTOMER");

        User savedUser = new User();
        savedUser.setId(1);
        savedUser.setFirstName("Test");
        savedUser.setLastName("User");
        savedUser.setEmail("test@example.com");
        savedUser.setPassword("encodedPassword");
        savedUser.setRole(defaultRole);

        UserDetailsImpl userDetails = UserDetailsImpl.build(savedUser);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(savedUser);
        TokenPair tokenPair = new TokenPair(refreshToken, "raw-refresh-token");

        when(userService.existsByEmail("test@example.com")).thenReturn(false);
        when(roleService.findByName("ROLE_CUSTOMER")).thenReturn(Optional.of(defaultRole));
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");
        when(userService.save(any(User.class))).thenReturn(savedUser);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtUtils.generateTokenByAuth(any(Authentication.class))).thenReturn("test.jwt.token");
        when(jwtUtils.getJwtExpirationMs()).thenReturn(300000L);
        when(refreshTokenService.createRefreshToken(any(User.class), any(), any()))
                .thenReturn(tokenPair);

        mockMvc.perform(post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").value("test.jwt.token"))
                .andExpect(jsonPath("$.email").value("test@example.com"));

        verify(userService, times(1)).save(any(User.class));
    }

    @Test
    void testSignup_WithExistingEmail_ReturnsError() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setFirstName("Test");
        signUpRequest.setLastName("User");
        signUpRequest.setEmail("existing@example.com");
        signUpRequest.setPassword("password123");

        when(userService.existsByEmail("existing@example.com")).thenReturn(true);

        mockMvc.perform(post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Email already exists !"));

        verify(userService, never()).save(any(User.class));
    }

    @Test
    void testSignin_WithValidCredentials_ReturnsJwtToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        Role role = new Role();
        role.setId(1);
        role.setName("ROLE_CUSTOMER");

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

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        TokenPair tokenPair = new TokenPair(refreshToken, "raw-refresh-token");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtUtils.generateTokenByAuth(any(Authentication.class))).thenReturn("test.jwt.token");
        when(jwtUtils.getJwtExpirationMs()).thenReturn(300000L);
        when(userService.findById(1)).thenReturn(Optional.of(user));
        when(refreshTokenService.createRefreshToken(any(User.class), any(), any()))
                .thenReturn(tokenPair);

        mockMvc.perform(post("/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("test.jwt.token"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("ROLE_CUSTOMER"));
    }
}
