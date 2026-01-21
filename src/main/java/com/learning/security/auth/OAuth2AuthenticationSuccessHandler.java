package com.learning.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.security.dtos.TokenPair;
import com.learning.security.models.User;
import com.learning.security.payload.response.AuthResponse;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.JwtUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

/**
 * <h2>OAuth2AuthenticationSuccessHandler</h2>
 * <p>
 * Handles successful OAuth2 authentication by generating JWT access token and refresh token
 * Returns JSON response instead of redirecting
 * Sets refresh token in secure HttpOnly cookie
 * </p>
 */
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private ObjectMapper objectMapper;

    @Value("#{'${yousuf.app.oauth2.authorized-redirect-uris}'.split(',')}")
    private List<String> authorizedRedirectUris;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        
        if (response.isCommitted()) {
            logger.debug("Response has already been committed.");
            return;
        }

        try {
            // Generate access token (5 minutes)
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            // Get user details
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String role = userDetails.getAuthorities().iterator().next().getAuthority();

            // Get user entity for refresh token creation
            User user = userRepo.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate refresh token (7 days) and set in secure cookie
            // OAuth2 client ID extracted from registration if available
            String oauthClientId = "google"; // Can be made dynamic based on provider
            TokenPair tokenPair = refreshTokenService.createRefreshToken(user, request, oauthClientId);
            setRefreshTokenCookie(response, tokenPair.getRawToken());

            // Build JSON response
            AuthResponse authResponse = new AuthResponse(
                    accessToken,
                    userDetails.getId(),
                    userDetails.getEmail(),
                    role,
                    jwtUtils.getJwtExpirationMs()
            );

            // Write JSON response
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write(objectMapper.writeValueAsString(authResponse));
            response.getWriter().flush();

            logger.info("OAuth2 authentication successful for user: {}", userDetails.getEmail());

        } catch (Exception e) {
            logger.error("Error during OAuth2 authentication success handling", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\": \"Authentication successful but token generation failed\"}");
        }
    }

    /**
     * Set refresh token in secure HttpOnly cookie
     */
    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);  // Prevent JavaScript access
        cookie.setSecure(false);    // Set to true in production with HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
        cookie.setAttribute("SameSite", "Lax"); // CSRF protection
        response.addCookie(cookie);
    }
}
