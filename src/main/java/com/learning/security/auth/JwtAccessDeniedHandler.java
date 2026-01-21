package com.learning.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * <h2>JwtAccessDeniedHandler</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class implements <code>AccessDeniedHandler</code> to handle cases where an authenticated user tries to access a resource they do not have permission for.<br>
 * </p>
 * <ul>
 *   <li>Intercepts requests where access is denied due to insufficient authorities.</li>
 *   <li>Returns a JSON response with HTTP 403 status and error details.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Automatically invoked by Spring Security when an <code>AccessDeniedException</code> is thrown for an authenticated user.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>The client receives a JSON error response with status 403 (Forbidden).</li>
 *   <li>No further processing of the request occurs.</li>
 * </ul>
 */
@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    /**
     * <h3>handle</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Handles access denied exceptions by sending a structured JSON error response.<br>
     * </p>
     * <ul>
     *   <li>Builds a JSON response with error details and the request path.</li>
     *   <li>Sets the HTTP status to 403 (Forbidden).</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring Security when an authenticated user lacks required permissions.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The response is sent to the client and the request is not processed further.</li>
     * </ul>
     * @param request the HTTP request
     * @param response the HTTP response
     * @param accessDeniedException the exception indicating access was denied
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        final Map<String, Object> body = new HashMap<>();
        body.put("Status", HttpServletResponse.SC_FORBIDDEN);
        body.put("Error", "Forbidden");
        body.put("Message", accessDeniedException.getMessage());
        body.put("Path", request.getServletPath());

        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}