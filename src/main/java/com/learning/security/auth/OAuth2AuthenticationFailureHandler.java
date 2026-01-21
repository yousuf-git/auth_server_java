package com.learning.security.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    @Value("#{'${yousuf.app.oauth2.authorized-redirect-uris}'.split(',')}")
    private List<String> authorizedRedirectUris;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        
        String targetUrl = authorizedRedirectUris.isEmpty() ? "/" : authorizedRedirectUris.get(0);

        logger.error("OAuth2 authentication failed: {}", exception.getLocalizedMessage());

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
