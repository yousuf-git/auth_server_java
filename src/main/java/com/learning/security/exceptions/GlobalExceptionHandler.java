package com.learning.security.exceptions;

import com.learning.security.dtos.ResponseMessage;
import jakarta.validation.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import lombok.extern.slf4j.Slf4j;

import org.springframework.validation.FieldError;

import java.util.HashMap;
import java.util.Map;

/**
 * <h2>GlobalExceptionHandler</h2>
 * <p> 
* <b>Purpose:</b><br>
 * This class acts as a centralized exception handler for the entire application. That's why Annotated with @RestControllerAdvice <br>
 * </p>
 * <ul>
 *   <li>Handles exceptions thrown by controllers and other components globally.</li>
 *   <li>Provides custom responses for validation and other errors.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Automatically invoked by Spring when an exception is thrown in any controller.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>Returns a structured error response to the client, typically as JSON.</li>
 *   <li>Prevents the application from returning default error pages.</li>
 * </ul>
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    // ──────────────────────────── Validation Errors ────────────────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, Object> response = new HashMap<>();
        Map<String, String> fieldErrors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(error.getField(), error.getDefaultMessage());
        }
        response.put("error", "Validation failed");
        response.put("fields", fieldErrors);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ResponseMessage> handleConstraintViolation(ConstraintViolationException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage("Invalid request parameters"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ResponseMessage> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage("Malformed request body"));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ResponseMessage> handleMissingParameter(MissingServletRequestParameterException ex) {
        String message = String.format("Required parameter '%s' of type '%s' is missing",
                ex.getParameterName(), ex.getParameterType());
        return ResponseEntity.badRequest().body(new ResponseMessage(message));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ResponseMessage> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String message = String.format("Parameter '%s' should be of type '%s'",
                ex.getName(), ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown");
        return ResponseEntity.badRequest().body(new ResponseMessage(message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ResponseMessage> handleIllegalArgument(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage(ex.getMessage()));
    }

    // ──────────────────────────── Business / Domain Errors ────────────────────────────

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ResponseMessage> handleBadRequest(BadRequestException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage(ex.getMessage()));
    }

    @ExceptionHandler(OtpException.class)
    public ResponseEntity<ResponseMessage> handleOtpException(OtpException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage(ex.getMessage()));
    }

    // ──────────────────────────── Security Errors ────────────────────────────

    @ExceptionHandler(AccessDeniedException.class)
    public void handleAccessDenied(AccessDeniedException ex) throws AccessDeniedException {
        throw ex; // Re-throw so Spring Security's AccessDeniedHandler returns 403
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ResponseMessage> handleLocked(LockedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ResponseMessage("Account is locked. Please contact administrator."));
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ResponseMessage> handleDisabled(DisabledException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ResponseMessage("Account is disabled."));
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ResponseMessage> handleBadCredentials(BadCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ResponseMessage("Invalid credentials."));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ResponseMessage> handleAuthenticationException(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ResponseMessage("Authentication failed."));
    }

    // ──────────────────────────── HTTP / Routing Errors ────────────────────────────

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ResponseMessage> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        String message = String.format("Method '%s' is not supported for this endpoint. Supported methods: %s",
                ex.getMethod(), ex.getSupportedHttpMethods());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(new ResponseMessage(message));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ResponseMessage> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        String message = String.format("Content type '%s' is not supported. Supported types: %s",
                ex.getContentType(), ex.getSupportedMediaTypes());
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(new ResponseMessage(message));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ResponseMessage> handleNoHandlerFound(NoHandlerFoundException ex) {
        String message = String.format("Endpoint '%s' not found", ex.getRequestURL());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ResponseMessage(message));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ResponseMessage> handleNoResourceFound(NoResourceFoundException ex) {
        String message = String.format("Resource '%s' not found", ex.getResourcePath());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ResponseMessage(message));
    }

    // ──────────────────────────── Data Errors ────────────────────────────

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ResponseMessage> handleDataIntegrity(DataIntegrityViolationException ex) {
        log.warn("Data integrity violation: {}", ex.getMostSpecificCause().getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ResponseMessage("Data conflict: a record with the same unique value already exists."));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ResponseMessage> handleMaxUploadSize(MaxUploadSizeExceededException ex) {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .body(new ResponseMessage("File size exceeds the allowed limit."));
    }

    // ──────────────────────────── Catch-All ────────────────────────────

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseMessage> handleGeneral(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ResponseMessage("An unexpected error occurred. Please try again later."));
    }
}
