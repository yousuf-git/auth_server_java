package com.learning.security.exceptions;

import org.springframework.security.core.AuthenticationException;

/**
 * <h2>OAuth2AuthenticationProcessingException</h2>
 * <p>
 * Custom exception for OAuth2 authentication processing errors
 * </p>
 */
public class OAuth2AuthenticationProcessingException extends AuthenticationException {
    
    public OAuth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
    
    public OAuth2AuthenticationProcessingException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
