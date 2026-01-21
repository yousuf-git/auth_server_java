package com.learning.security.dtos;

import com.learning.security.models.RefreshToken;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * <h2>TokenPair</h2>
 * <p>
 * Internal DTO to hold both RefreshToken entity and raw token string
 * Used when creating/rotating tokens
 * </p>
 */
@Data
@AllArgsConstructor
public class TokenPair {
    
    /**
     * RefreshToken entity (saved in database)
     */
    private RefreshToken refreshToken;
    
    /**
     * Raw refresh token string (to be sent to client)
     * Never stored in database - only the hash is stored
     */
    private String rawToken;
}
