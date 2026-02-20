package com.learning.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.learning.security.dtos.TokenPair;
import com.learning.security.models.User;
import com.learning.security.payload.response.AuthResponse;
import com.learning.security.services.UserService;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.CookieUtils;
import com.learning.security.utils.JwtUtils;
import com.learning.security.utils.OAuth2CookieUtils;
import jakarta.servlet.ServletException;
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
    private UserService userService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CookieUtils cookieUtils;

    @Autowired
    private OAuth2CookieUtils oauth2CookieUtils;

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
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String role = userDetails.getAuthorities().iterator().next().getAuthority();

            User user = userService.findById(userDetails.getId())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            // Generate refresh token (7 days) and set in secure cookie
            // OAuth2 client ID extracted from registration if available
            String oauthClientId = "google"; // Can be made dynamic based on provider
            TokenPair tokenPair = refreshTokenService.createRefreshToken(user, request, oauthClientId);
            cookieUtils.setRefreshTokenCookie(response, tokenPair.getRawToken());

            // Build redirect URL with token for frontend
            String targetUrl = determineRedirectUrl(request, accessToken, user, role);
            
            // Clear OAuth2 cookies after use
            oauth2CookieUtils.clearOAuth2Cookies(request, response);
            
            // Redirect to frontend
            getRedirectStrategy().sendRedirect(request, response, targetUrl);

            logger.info("OAuth2 authentication successful for user: {}", userDetails.getEmail());

        } catch (Exception e) {
            logger.error("Error during OAuth2 authentication success handling", e);
            
            // Try to get client's error URI from cookie
            String errorUrl = oauth2CookieUtils.getErrorUriCookie(request)
                    .orElse(authorizedRedirectUris.isEmpty() ? "/" : authorizedRedirectUris.get(0));
            errorUrl = errorUrl + "?error=" + e.getMessage();
            
            oauth2CookieUtils.clearOAuth2Cookies(request, response);
            getRedirectStrategy().sendRedirect(request, response, errorUrl);
        }
    }

    /**
     * Build redirect URL with token and user info for frontend
     * Uses client-provided redirect_uri from cookie, falls back to configured URI
     */
    private String determineRedirectUrl(HttpServletRequest request, String accessToken, User user, String role) {
        // Try to get client's redirect URI from cookie
        String targetUrl = oauth2CookieUtils.getRedirectUriCookie(request)
                .orElse(authorizedRedirectUris.isEmpty() ? "http://localhost:3000" : authorizedRedirectUris.get(0));
        
        logger.info("Redirecting OAuth2 user to: {}", targetUrl);
        
        return targetUrl + "?" +
                "accessToken=" + accessToken +
                "&tokenType=Bearer" +
                "&userId=" + user.getId() +
                "&email=" + user.getEmail() +
                "&role=" + role +
                "&expiresIn=" + jwtUtils.getJwtExpirationMs() +
                "&emailVerified=" + user.getEmailVerified();
    }
}
