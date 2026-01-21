package com.learning.security.exceptions;

import lombok.Getter;

/**
 * <h2>CustomJwtException</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class represents a custom exception for JWT-related errors.<br>
 * </p>
 * <ul>
 *   <li>Allows attaching an HTTP status code to the exception for more granular error handling.</li>
 *   <li>Used to signal specific JWT validation or parsing issues throughout the authentication process.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Thrown by JWT utility methods when a token is invalid, expired, or malformed.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>The exception is caught by filters or handlers, which use its status and message for the HTTP response.</li>
 * </ul>
 */
@Getter
public class CustomJwtException extends RuntimeException {
    private final int statusCode;

    /**
     * <h3>CustomJwtException constructor</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Constructs a new CustomJwtException with a message and HTTP status code.<br>
     * </p>
     * <ul>
     *   <li>Allows passing a custom error message and status code for JWT errors.</li>
     * </ul>
     * @param message the error message
     * @param statusCode the HTTP status code to associate with this exception
     */
    public CustomJwtException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

}
