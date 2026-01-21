// Handle Authentication Exception

package com.learning.security.auth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.learning.security.exceptions.CustomJwtException;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;

/**
 * <h2>AuthEntryPointJwt</h2>
 * <p>
 * <b>Purpose:</b> <br>
 * This class is a custom implementation of Spring Security's <code>AuthenticationEntryPoint</code> interface.<br>
 * It is responsible for handling authentication errors for protected resources.<br>
 * </p>
 * <ul>
 *   <li>When an unauthenticated user tries to access a secured endpoint, this entry point is triggered.</li>
 *   <li>It customizes the response sent to the client, providing a JSON error message instead of the default HTML error page.</li>
 *   <li>It can also handle custom JWT exceptions and return appropriate status codes and messages.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Automatically invoked by Spring Security when an <code>AuthenticationException</code> is thrown due to missing or invalid authentication.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>The client receives a JSON response with error details and the HTTP status code (typically 401 Unauthorized).</li>
 *   <li>No further processing of the request occurs.</li>
 * </ul>
 */
@Component
//@Slf4j
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    Logger log = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    /**
     * <h3>commence</h3>
     * <p>
     * <b>Purpose:</b> <br>
     * Handles the start of the authentication process when an unauthenticated user attempts to access a secured resource.<br>
     * </p>
     * <ul>
     *   <li>Builds a JSON error response with details about the authentication failure.</li>
     *   <li>If a <code>CustomJwtException</code> is present in the request, it uses its status and message.</li>
     *   <li>Otherwise, it returns a generic unauthorized error.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring Security when authentication fails for a protected endpoint.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The response is sent to the client and the request is not processed further.</li>
     * </ul>
     * @param request the HTTP request that resulted in an AuthenticationException
     * @param response the HTTP response to send the error details
     * @param authException the exception that caused the authentication failure
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) {
        try {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            final Map<String, Object> body = new HashMap<>();
//            body.put("Status", HttpServletResponse.SC_UNAUTHORIZED);
            body.put("Path", request.getServletPath());
            // Check for stored JWT exception first
            CustomJwtException jwtException = (CustomJwtException) request.getAttribute("jwt.exception");

//            if (authException.getCause() instanceof CustomJwtException) {
//                CustomJwtException jwtException = (CustomJwtException) authException.getCause();
//                response.setStatus(jwtException.getStatusCode());
//                body.put("Error", jwtException.getMessage());
//            } else {
//                body.put("Error", "Unauthorized!");
//                body.put("Message", authException.getMessage());
//            }
            if (jwtException != null) {
                response.setStatus(jwtException.getStatusCode());
                body.put("Status", jwtException.getStatusCode());
                body.put("Error", jwtException.getMessage());
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                body.put("Status", HttpServletResponse.SC_UNAUTHORIZED);
                body.put("Error", "Unauthorized!");
                body.put("Message", authException.getMessage());
            }

            final ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(response.getOutputStream(), body);
            log.error("Auth Error: {} ", authException.getMessage());
        } catch (IOException e) {
            log.error(e.getMessage());
        }
    }
}
