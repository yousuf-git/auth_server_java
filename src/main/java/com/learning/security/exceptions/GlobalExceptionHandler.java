package com.learning.security.exceptions;

import com.learning.security.dtos.ResponseMessage;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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

    /**
     * <h3>handleValidationExceptions</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Handles validation errors for method arguments annotated with @Valid. <br>
     * </p>
     * <ul>
     *   <li>Collects all field errors and returns them in a map.</li>
     *   <li>Responds with HTTP 400 Bad Request and error details.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring when a MethodArgumentNotValidException is thrown.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The client receives a map of field errors and their messages.</li>
     * </ul>
     * @param ex the MethodArgumentNotValidException thrown
     * @return ResponseEntity containing error details and HTTP status
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ResponseMessage> handleConstraintViolation(ConstraintViolationException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage("Invalid request parameters"));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ResponseMessage> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage("Malformed request body"));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public void handleAccessDenied(AccessDeniedException ex) throws AccessDeniedException {
        throw ex; // Re-throw so Spring Security's AccessDeniedHandler returns 403
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseMessage> handleGeneral(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ResponseMessage("An unexpected error occurred"));
    }
}
