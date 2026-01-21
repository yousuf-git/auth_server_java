package com.learning.security.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for TestController
 * Tests role-based access control for various endpoints
 */
@SpringBootTest
@AutoConfigureMockMvc
class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void testPublicEndpoint_WithoutAuthentication() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("This endpoint is available for all"));
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void testPublicEndpoint_WithUserRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("This endpoint is available for all"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testPublicEndpoint_WithAdminRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk())
                .andExpect(content().string("This endpoint is available for all"));
    }

    @Test
    void testUserEndpoint_WithoutAuthentication() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void testUserEndpoint_WithUserRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User's Content is here :)"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testUserEndpoint_WithAdminRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User's Content is here :)"));
    }

    @Test
    @WithMockUser(username = "mod", roles = {"MODERATOR"})
    void testUserEndpoint_WithModeratorRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk())
                .andExpect(content().string("User's Content is here :)"));
    }

    @Test
    void testModEndpoint_WithoutAuthentication() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void testModEndpoint_WithUserRole() throws Exception {
        // When & Then - User should not have access to moderator endpoint
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "mod", roles = {"MODERATOR"})
    void testModEndpoint_WithModeratorRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk())
                .andExpect(content().string("Mod's Content is here :)"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testModEndpoint_WithAdminRole() throws Exception {
        // When & Then - Admin should have access to moderator endpoint
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk())
                .andExpect(content().string("Mod's Content is here :)"));
    }

    @Test
    void testAdminEndpoint_WithoutAuthentication() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user", roles = {"USER"})
    void testAdminEndpoint_WithUserRole() throws Exception {
        // When & Then - User should not have access to admin endpoint
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "mod", roles = {"MODERATOR"})
    void testAdminEndpoint_WithModeratorRole() throws Exception {
        // When & Then - Moderator should not have access to admin endpoint
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testAdminEndpoint_WithAdminRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isOk())
                .andExpect(content().string("Admin's Content is here :)"));
    }

    @Test
    @WithMockUser(username = "superuser", roles = {"USER", "MODERATOR", "ADMIN"})
    void testAllEndpoints_WithAllRoles() throws Exception {
        // Given - User with all roles
        
        // When & Then - Should have access to all endpoints
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testRoleHierarchy_UserAccessLevel() throws Exception {
        // Given - User with only USER role
        
        // When & Then
        // Can access public endpoint
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk());
        
        // Can access user endpoint
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        // Cannot access moderator endpoint
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isForbidden());
        
        // Cannot access admin endpoint
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "testmod", roles = {"MODERATOR"})
    void testRoleHierarchy_ModeratorAccessLevel() throws Exception {
        // Given - User with only MODERATOR role
        
        // When & Then
        // Can access public endpoint
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk());
        
        // Can access user endpoint (moderators can access user content)
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        // Can access moderator endpoint
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk());
        
        // Cannot access admin endpoint
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "testadmin", roles = {"ADMIN"})
    void testRoleHierarchy_AdminAccessLevel() throws Exception {
        // Given - User with only ADMIN role
        
        // When & Then
        // Can access all endpoints
        mockMvc.perform(get("/test/all"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "combo", roles = {"USER", "MODERATOR"})
    void testCombinedRoles_UserAndModerator() throws Exception {
        // Given - User with USER and MODERATOR roles
        
        // When & Then - Should have moderator level access
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "combo", roles = {"USER", "ADMIN"})
    void testCombinedRoles_UserAndAdmin() throws Exception {
        // Given - User with USER and ADMIN roles
        
        // When & Then - Should have full access
        mockMvc.perform(get("/test/user"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/mod"))
                .andExpect(status().isOk());
        
        mockMvc.perform(get("/test/admin"))
                .andExpect(status().isOk());
    }

    @Test
    void testCorsHeaders_PublicEndpoint() throws Exception {
        // When & Then - Verify CORS headers are set
        mockMvc.perform(get("/test/all")
                .header("Origin", "http://example.com"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Access-Control-Allow-Origin"));
    }
}
