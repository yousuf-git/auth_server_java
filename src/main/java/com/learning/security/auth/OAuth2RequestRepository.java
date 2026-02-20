package com.learning.security.auth;

import com.learning.security.utils.OAuth2CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

/**
 * <h2>OAuth2RequestRepository</h2>
 * <p>
 * Custom authorization request repository that stores client redirect URIs
 * before OAuth2 flow and validates them against whitelist for security.
 * </p>
 */
@Component
public class OAuth2RequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Logger logger = LoggerFactory.getLogger(OAuth2RequestRepository.class);

    @Autowired
    private OAuth2CookieUtils oauth2CookieUtils;

    @Value("#{'${yousuf.app.oauth2.authorized-redirect-uris}'.split(',')}")
    private List<String> authorizedRedirectUris;

    private final AuthorizationRequestRepository<OAuth2AuthorizationRequest> defaultRepository =
            new org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository();

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return defaultRepository.loadAuthorizationRequest(request);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                        HttpServletRequest request,
                                        HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequest(request, response);
            return;
        }

        // Extract and validate redirect URIs from request
        String redirectUri = request.getParameter(OAuth2CookieUtils.REDIRECT_URI_PARAM);
        String errorUri = request.getParameter(OAuth2CookieUtils.ERROR_URI_PARAM);

        if (redirectUri != null && !redirectUri.isBlank()) {
            if (isAuthorizedRedirectUri(redirectUri)) {
                oauth2CookieUtils.addRedirectUriCookie(response, redirectUri);
                logger.debug("Stored client redirect URI: {}", redirectUri);
            } else {
                logger.warn("Unauthorized redirect URI attempted: {}", redirectUri);
            }
        }

        if (errorUri != null && !errorUri.isBlank()) {
            if (isAuthorizedRedirectUri(errorUri)) {
                oauth2CookieUtils.addErrorUriCookie(response, errorUri);
                logger.debug("Stored client error URI: {}", errorUri);
            } else {
                logger.warn("Unauthorized error URI attempted: {}", errorUri);
            }
        }

        defaultRepository.saveAuthorizationRequest(authorizationRequest, request, response);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                 HttpServletResponse response) {
        return defaultRepository.removeAuthorizationRequest(request, response);
    }

    /**
     * Validate redirect URI against whitelist
     * Checks if the URI starts with any of the authorized base URIs
     */
    private boolean isAuthorizedRedirectUri(String uri) {
        if (uri == null || uri.isBlank()) {
            return false;
        }

        try {
            URI clientRedirectUri = URI.create(uri);
            String uriString = clientRedirectUri.toString();

            return authorizedRedirectUris.stream()
                    .anyMatch(authorizedUri -> {
                        // Allow exact match or subpath of authorized URI
                        URI authorizedRedirect = URI.create(authorizedUri);
                        return uriString.startsWith(authorizedRedirect.toString()) ||
                               (clientRedirectUri.getHost() != null &&
                                clientRedirectUri.getHost().equals(authorizedRedirect.getHost()) &&
                                clientRedirectUri.getScheme().equals(authorizedRedirect.getScheme()));
                    });
        } catch (Exception e) {
            logger.error("Invalid URI format: {}", uri, e);
            return false;
        }
    }
}
