package com.learning.security.auth;

import com.learning.security.utils.OAuth2CookieUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;

/**
 * <h2>OAuth2AuthenticationFailureHandler</h2>
 * <p>
 * Handles OAuth2 authentication failures by redirecting user with error message
 * </p>
 */
@Component
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2AuthenticationFailureHandler.class);

    @Autowired
    private OAuth2CookieUtils oauth2CookieUtils;

    @Value("#{'${yousuf.app.oauth2.authorized-redirect-uris}'.split(',')}")
    private List<String> authorizedRedirectUris;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        
        // Try to get client's error URI from cookie, fallback to configured URI
        String targetUrl = oauth2CookieUtils.getErrorUriCookie(request)
                .orElse(authorizedRedirectUris.isEmpty() ? "/" : authorizedRedirectUris.get(0));

        logger.error("OAuth2 authentication failed: {}", exception.getLocalizedMessage());

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        // Clear OAuth2 cookies
        oauth2CookieUtils.clearOAuth2Cookies(request, response);

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
