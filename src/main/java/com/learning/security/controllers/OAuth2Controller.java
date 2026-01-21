package com.learning.security.controllers;

import com.learning.security.services.UserDetailsImpl;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * <h2>OAuth2Controller</h2>
 * <p>
 * REST controller for OAuth2 authentication endpoints
 * </p>
 */
@RestController
@RequestMapping("/oauth2")
@Tag(name = "OAuth2 Authentication", description = "OAuth2 authentication endpoints for Google login")
public class OAuth2Controller {

    @GetMapping("/user")
    @Operation(summary = "Get current OAuth2 user", 
               description = "Returns the currently authenticated OAuth2 user information")
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", userDetails.getId());
        response.put("username", userDetails.getUsername());
        response.put("email", userDetails.getEmail());
        response.put("roles", userDetails.getAuthorities());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/redirect")
    @Operation(summary = "OAuth2 redirect endpoint", 
               description = "Endpoint to handle OAuth2 redirect after authentication. " +
                           "This is typically used by frontend applications.")
    public ResponseEntity<Map<String, String>> oauth2Redirect() {
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "OAuth2 authentication successful");
        response.put("note", "Frontend should extract token from URL parameters");
        
        return ResponseEntity.ok(response);
    }
}
