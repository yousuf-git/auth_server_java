package com.learning.security.exceptions;

/**
 * Exception for OTP-related errors: expired, invalid, rate-limited, etc.
 */
public class OtpException extends RuntimeException {

    public OtpException(String message) {
        super(message);
    }

    public OtpException(String message, Throwable cause) {
        super(message, cause);
    }
}
