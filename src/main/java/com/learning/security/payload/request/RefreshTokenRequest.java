package com.learning.security.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <h2>RefreshTokenRequest</h2>
 * <p>
 * Request DTO for token refresh endpoint
 * Note: Refresh token typically sent as HttpOnly cookie
 * This DTO is for alternative implementations
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenRequest {
    
    /**
     * Refresh token from cookie or request body
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
