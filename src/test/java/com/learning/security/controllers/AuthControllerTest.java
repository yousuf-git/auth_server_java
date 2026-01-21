package com.learning.security.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.security.dtos.LoginRequest;
import com.learning.security.dtos.SignUpRequest;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.repos.RoleRepo;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.UserDetailsImpl;
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
    private UserRepo userRepo;

    @MockitoBean
    private RoleRepo roleRepo;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private JwtUtils jwtUtils;

    private Role defaultRole;

    @BeforeEach
    void setUp() {
        defaultRole = new Role();
        defaultRole.setId(1);
        defaultRole.setName("ROLE_USER");
    }

    @Test
    void testSignup_WithValidData_CreatesUser() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setEmail("test@example.com");
        signUpRequest.setPassword("password123");
        signUpRequest.setRole("ROLE_USER");

        when(userRepo.existsByEmail("test@example.com")).thenReturn(false);
        when(roleRepo.findByName("ROLE_USER")).thenReturn(Optional.of(defaultRole));
        when(passwordEncoder.encode("password123")).thenReturn("encodedPassword");

        mockMvc.perform(post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User registered successfully!"));

        verify(userRepo, times(1)).save(any(User.class));
    }

    @Test
    void testSignup_WithExistingEmail_ReturnsError() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest();
        signUpRequest.setEmail("existing@example.com");
        signUpRequest.setPassword("password123");

        when(userRepo.existsByEmail("existing@example.com")).thenReturn(true);

        mockMvc.perform(post("/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Error: Email is already in use!"));

        verify(userRepo, never()).save(any(User.class));
    }

    @Test
    void testSignin_WithValidCredentials_ReturnsJwtToken() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        Role role = new Role();
        role.setId(1);
        role.setName("ROLE_USER");
        
        User user = new User();
        user.setId(1);
        user.setEmail("test@example.com");
        user.setPassword("encodedPassword");
        user.setRole(role);

        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(authentication);
        when(jwtUtils.generateTokenByAuth(authentication)).thenReturn("test.jwt.token");

        mockMvc.perform(post("/auth/signin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("test.jwt.token"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"));
    }
}
