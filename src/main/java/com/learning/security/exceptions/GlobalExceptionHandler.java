package com.learning.security.exceptions;

import com.learning.security.dtos.ResponseMessage;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
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

    @ExceptionHandler(OtpException.class)
    public ResponseEntity<ResponseMessage> handleOtpException(OtpException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage(ex.getMessage()));
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ResponseMessage> handleBadRequest(BadRequestException ex) {
        return ResponseEntity.badRequest().body(new ResponseMessage(ex.getMessage()));
    }

    /**
     * <h3>handleMethodNotSupported</h3>
     * <p>Handles HTTP 405 Method Not Allowed errors</p>
     * <p>Returns HTTP 405 when client uses wrong HTTP method (e.g., GET instead of POST)</p>
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ResponseMessage> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex) {
        String message = String.format("Method '%s' is not supported for this endpoint. Supported methods: %s",
                ex.getMethod(), ex.getSupportedHttpMethods());
        log.warn("Method not supported: {}", message);
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(new ResponseMessage(message));
    }

    /**
     * <h3>handleMediaTypeNotSupported</h3>
     * <p>Handles HTTP 415 Unsupported Media Type errors</p>
     * <p>Returns HTTP 415 when client sends content with unsupported Content-Type</p>
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ResponseMessage> handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex) {
        String message = String.format("Content type '%s' is not supported. Supported types: %s",
                ex.getContentType(), ex.getSupportedMediaTypes());
        log.warn("Media type not supported: {}", message);
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(new ResponseMessage(message));
    }

    /**
     * <h3>handleMissingParameter</h3>
     * <p>Handles HTTP 400 Bad Request for missing required parameters</p>
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ResponseMessage> handleMissingParameter(MissingServletRequestParameterException ex) {
        String message = String.format("Required parameter '%s' of type '%s' is missing",
                ex.getParameterName(), ex.getParameterType());
        log.warn("Missing request parameter: {}", message);
        return ResponseEntity.badRequest().body(new ResponseMessage(message));
    }

    /**
     * <h3>handleTypeMismatch</h3>
     * <p>Handles HTTP 400 Bad Request for parameter type conversion failures</p>
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ResponseMessage> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        String message = String.format("Parameter '%s' should be of type '%s'",
                ex.getName(), ex.getRequiredType() != null ? ex.getRequiredType().getSimpleName() : "unknown");
        log.warn("Type mismatch: {}", message);
        return ResponseEntity.badRequest().body(new ResponseMessage(message));
    }

    /**
     * <h3>handleNoHandlerFound</h3>
     * <p>Handles HTTP 404 Not Found errors (legacy)</p>
     * <p>Requires spring.mvc.throw-exception-if-no-handler-found=true in application.yml</p>
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ResponseMessage> handleNoHandlerFound(NoHandlerFoundException ex) {
        String message = String.format("Endpoint '%s' not found", ex.getRequestURL());
        log.warn("No handler found: {}", message);
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ResponseMessage(message));
    }

    /**
     * <h3>handleNoResourceFound</h3>
     * <p>Handles HTTP 404 Not Found errors for static resources and unmapped endpoints</p>
     * <p>This is the modern Spring 6+ replacement for NoHandlerFoundException</p>
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ResponseMessage> handleNoResourceFound(NoResourceFoundException ex) {
        String message = String.format("Resource '%s' not found", ex.getResourcePath());
        log.warn("No resource found: {}", message);
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ResponseMessage(message));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseMessage> handleGeneral(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ResponseMessage("An unexpected error occurred"));
    }
}
