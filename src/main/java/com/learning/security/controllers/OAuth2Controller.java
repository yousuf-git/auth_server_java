package com.learning.security.controllers;

import com.learning.security.dtos.TokenPair;
import com.learning.security.models.User;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.services.UserService;
import com.learning.security.utils.CookieUtils;
import com.learning.security.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <h2>OAuth2Controller</h2>
 * <p>
 * REST controller for OAuth2 2.0 compliant endpoints.
 * Implements the OAuth2 token endpoint (RFC 6749) and token introspection endpoint (RFC 7662).
 * </p>
 *
 * <h3>Supported Flows:</h3>
 * <ul>
 *   <li><b>Authorization Code (Google OAuth2):</b> GET /oauth2/authorize/google (handled by Spring Security)</li>
 *   <li><b>Resource Owner Password Credentials:</b> POST /oauth2/token with grant_type=password</li>
 *   <li><b>Refresh Token:</b> POST /oauth2/token with grant_type=refresh_token</li>
 *   <li><b>Token Introspection:</b> POST /oauth2/introspect (RFC 7662)</li>
 * </ul>
 */
@RestController
@RequestMapping("/oauth2")
@Tag(name = "OAuth2 Authentication", description = "OAuth2 2.0 compliant token and introspection endpoints")
public class OAuth2Controller {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2Controller.class);

    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private CookieUtils cookieUtils;

    // ──────────────────────────── OAuth2 Token Endpoint ────────────────────────────

    /**
     * OAuth2 Token Endpoint (RFC 6749 Section 3.2)
     * <p>
     * Supports:
     * - grant_type=password (Resource Owner Password Credentials)
     * - grant_type=refresh_token (Refresh Token Grant)
     * </p>
     *
     * @param grantType  "password" or "refresh_token"
     * @param username   User email (required for password grant)
     * @param password   User password (required for password grant)
     * @param refreshToken Refresh token (required for refresh_token grant, reads from cookie if not provided)
     * @param scope      Requested scope (optional)
     */
    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "OAuth2 Token Endpoint",
               description = "Issue access tokens via password credentials or refresh token grant")
    public ResponseEntity<?> token(
            @RequestParam("grant_type") String grantType,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "password", required = false) String password,
            @RequestParam(value = "refresh_token", required = false) String refreshToken,
            @RequestParam(value = "scope", required = false) String scope,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        return switch (grantType) {
            case "password" -> handlePasswordGrant(username, password, httpRequest, httpResponse);
            case "refresh_token" -> handleRefreshTokenGrant(refreshToken, httpRequest, httpResponse);
            default -> {
                Map<String, Object> error = new LinkedHashMap<>();
                error.put("error", "unsupported_grant_type");
                error.put("error_description", "Grant type '" + grantType + "' is not supported. Use 'password' or 'refresh_token'.");
                yield ResponseEntity.badRequest().body(error);
            }
        };
    }

    /**
     * Handle Resource Owner Password Credentials Grant (RFC 6749 Section 4.3)
     */
    private ResponseEntity<?> handlePasswordGrant(String username, String password,
                                                   HttpServletRequest httpRequest,
                                                   HttpServletResponse httpResponse) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", "invalid_request");
            error.put("error_description", "Both 'username' and 'password' parameters are required for password grant.");
            return ResponseEntity.badRequest().body(error);
        }

        // Check if user exists and email is verified
        User user = userService.findByEmail(username).orElse(null);
        if (user == null) {
            return buildOAuth2Error("invalid_grant", "Invalid username or password.", HttpStatus.UNAUTHORIZED);
        }

        if (Boolean.FALSE.equals(user.getEmailVerified())) {
            Map<String, Object> error = new LinkedHashMap<>();
            error.put("error", "invalid_grant");
            error.put("error_description", "Email not verified. Please verify your email before logging in.");
            error.put("email", user.getEmail());
            error.put("action", "VERIFY_EMAIL");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
        }

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            
            User currentUser = userService.findById(userDetails.getId()).orElseThrow();

            TokenPair tokenPair = refreshTokenService.createRefreshToken(
                    currentUser,
                    httpRequest,
                    null
            );
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();
            
            // Extract permissions/scopes
            String scopes = "";
            if (currentUser.getRole() != null && currentUser.getRole().getPermissions() != null) {
                scopes = currentUser.getRole().getPermissions().stream()
                        .map(p -> p.getName())
                        .reduce((a, b) -> a + " " + b)
                        .orElse("");
            }

            // OAuth2-compliant token response (RFC 6749 Section 5.1)
            Map<String, Object> tokenResponse = new LinkedHashMap<>();
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("token_type", "Bearer");
            tokenResponse.put("expires_in", jwtUtils.getJwtExpirationMs() / 1000); // seconds per spec
            tokenResponse.put("refresh_token", tokenPair.getRawToken());
            tokenResponse.put("scope", role);
            tokenResponse.put("scopes", scopes);
            tokenResponse.put("user_id", userDetails.getId());
            tokenResponse.put("email", userDetails.getEmail());

            return ResponseEntity.ok(tokenResponse);

        } catch (LockedException e) {
            return buildOAuth2Error("invalid_grant", "Account is locked. Please contact administrator.", HttpStatus.FORBIDDEN);
        } catch (AuthenticationException e) {
            logger.error("Failed login attempt for email {}: {}", username, e.getMessage());
            return buildOAuth2Error("invalid_grant", "Invalid username or password.", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Handle Refresh Token Grant (RFC 6749 Section 6)
     */
    private ResponseEntity<?> handleRefreshTokenGrant(String refreshToken,
                                                       HttpServletRequest httpRequest,
                                                       HttpServletResponse httpResponse) {
        // Try from parameter first, then from cookie
        if (refreshToken == null || refreshToken.isBlank()) {
            refreshToken = cookieUtils.getRefreshTokenFromCookie(httpRequest);
        }

        if (refreshToken == null || refreshToken.isBlank()) {
            return buildOAuth2Error("invalid_request", "Refresh token is required.", HttpStatus.BAD_REQUEST);
        }

        try {
            TokenPair tokenPair = refreshTokenService.rotateRefreshToken(refreshToken, httpRequest);
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            User user = tokenPair.getRefreshToken().getUser();
            Authentication authentication = createAuthenticationFromUser(user);
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            String role = user.getRole() != null ? user.getRole().getName() : "";
            
            // Extract permissions/scopes
            String scopes = "";
            if (user.getRole() != null && user.getRole().getPermissions() != null) {
                scopes = user.getRole().getPermissions().stream()
                        .map(p -> p.getName())
                        .reduce((a, b) -> a + " " + b)
                        .orElse("");
            }

            Map<String, Object> tokenResponse = new LinkedHashMap<>();
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("token_type", "Bearer");
            tokenResponse.put("expires_in", jwtUtils.getJwtExpirationMs() / 1000);
            tokenResponse.put("refresh_token", tokenPair.getRawToken());
            tokenResponse.put("scope", role);
            tokenResponse.put("scopes", scopes);
            tokenResponse.put("user_id", user.getId());
            tokenResponse.put("email", user.getEmail());

            return ResponseEntity.ok(tokenResponse);

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(httpResponse);
            return buildOAuth2Error("invalid_grant", "Refresh token is invalid or expired. " + e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    // ──────────────────────────── Token Introspection ────────────────────────────

    /**
     * Token Introspection Endpoint (RFC 7662)
     * <p>
     * Allows Resource Servers to validate access tokens and retrieve associated metadata.
     * Returns an active/inactive indicator along with token claims.
     * </p>
     *
     * @param token The access token to introspect (required)
     */
    @PostMapping(value = "/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @Operation(summary = "Token Introspection (RFC 7662)",
               description = "Validate an access token and return its metadata. Used by Resource Servers.")
    public ResponseEntity<Map<String, Object>> introspectPost(
            @RequestParam("token") String token,
            @RequestParam(value = "token_type_hint", required = false) String tokenTypeHint) {
        return ResponseEntity.ok(buildIntrospectionResponse(token));
    }

    /**
     * Token Introspection via GET (convenience endpoint).
     * While RFC 7662 specifies POST, this GET endpoint is provided for simpler
     * Resource Server integrations.
     */
    @GetMapping("/introspect")
    @Operation(summary = "Token Introspection (GET)",
               description = "Validate an access token via query parameter. Convenience endpoint for Resource Servers.")
    public ResponseEntity<Map<String, Object>> introspectGet(
            @RequestParam("token") String token) {
        return ResponseEntity.ok(buildIntrospectionResponse(token));
    }

    /**
     * Build the introspection response per RFC 7662 Section 2.2
     */
    private Map<String, Object> buildIntrospectionResponse(String token) {
        Map<String, Object> response = new LinkedHashMap<>();

        if (token == null || token.isBlank()) {
            response.put("active", false);
            return response;
        }

        Claims claims = jwtUtils.getClaimsFromToken(token);

        if (claims == null) {
            // Token is invalid or expired
            response.put("active", false);
            return response;
        }

        // Token is valid — return claims per RFC 7662
        response.put("active", true);
        response.put("sub", claims.getSubject());
        response.put("username", claims.getSubject());
        response.put("scope", claims.get("scope", String.class));
        response.put("user_id", claims.get("user_id"));
        response.put("iss", claims.getIssuer());
        response.put("iat", claims.getIssuedAt().getTime() / 1000);
        response.put("exp", claims.getExpiration().getTime() / 1000);
        response.put("token_type", "Bearer");

        return response;
    }

    // ──────────────────────────── User Info ────────────────────────────

    @GetMapping("/user")
    @Operation(summary = "Get current OAuth2 user",
               description = "Returns the currently authenticated OAuth2 user information")
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal UserDetailsImpl userDetails) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("id", userDetails.getId());
        response.put("username", userDetails.getUsername());
        response.put("email", userDetails.getEmail());
        response.put("roles", userDetails.getAuthorities());

        return ResponseEntity.ok(response);
    }

    @GetMapping("/redirect")
    @Operation(summary = "OAuth2 redirect endpoint",
               description = "Endpoint to handle OAuth2 redirect after authentication. " +
                       "This is typically used by frontend applications.")
    public ResponseEntity<Map<String, String>> oauth2Redirect() {
        Map<String, String> response = new LinkedHashMap<>();
        response.put("message", "OAuth2 authentication successful");
        response.put("note", "Frontend should extract token from URL parameters");

        return ResponseEntity.ok(response);
    }

    // ──────────────────────────── Helpers ────────────────────────────

    private Authentication createAuthenticationFromUser(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        return new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    private ResponseEntity<Map<String, Object>> buildOAuth2Error(String error, String description, HttpStatus status) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("error_description", description);
        return ResponseEntity.status(status).body(body);
    }
}
