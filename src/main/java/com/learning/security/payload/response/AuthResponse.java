package com.learning.security.payload.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <h2>AuthResponse</h2>
 * <p>
 * Response DTO for authentication endpoints (signin, signup, OAuth2)
 * Returns access token in response body
 * Refresh token set as secure HttpOnly cookie
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    
    /**
     * Short-lived JWT access token (5 minutes)
     * Client stores in memory or localStorage
     */
    private String accessToken;
    
    /**
     * Token type (always "Bearer")
     */
    private String tokenType = "Bearer";
    
    /**
     * User ID
     */
    private Integer userId;
    
    /**
     * User email
     */
    private String email;
    
    /**
     * User role (ROLE_ADMIN, ROLE_MANAGER, ROLE_CUSTOMER)
     */
    private String role;
    
    /**
     * User permissions/scopes (space-separated)
     */
    private String scopes;
    
    /**
     * Access token expiration time in milliseconds
     */
    private Long expiresIn;

    /**
     * Whether the user's email has been verified
     */
    private Boolean emailVerified;

    /**
     * Constructor without emailVerified (backward compatible)
     */
    public AuthResponse(String accessToken, Integer userId, String email, String role, Long expiresIn) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.userId = userId;
        this.email = email;
        this.role = role;
        this.scopes = "";
        this.expiresIn = expiresIn;
        this.emailVerified = null;
    }

    /**
     * Full constructor with emailVerified
     */
    public AuthResponse(String accessToken, Integer userId, String email, String role, Long expiresIn, Boolean emailVerified) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.userId = userId;
        this.email = email;
        this.role = role;
        this.scopes = "";
        this.expiresIn = expiresIn;
        this.emailVerified = emailVerified;
    }
    
    /**
     * Full constructor with emailVerified and scopes
     */
    public AuthResponse(String accessToken, Integer userId, String email, String role, String scopes, Long expiresIn, Boolean emailVerified) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.userId = userId;
        this.email = email;
        this.role = role;
        this.scopes = scopes;
        this.expiresIn = expiresIn;
        this.emailVerified = emailVerified;
    }
}
