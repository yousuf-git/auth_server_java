package com.learning.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * <h2>CustomAuthorizationRequestResolver</h2>
 * <p>
 * Customizes OAuth2 authorization requests to add additional parameters like prompt=select_account
 * This forces Google to show account selection screen on every login attempt
 * </p>
 */
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;

    public CustomAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, 
                                             String authorizationRequestBaseUri) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
        return authorizationRequest != null ? customizeAuthorizationRequest(authorizationRequest) : null;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
        return authorizationRequest != null ? customizeAuthorizationRequest(authorizationRequest) : null;
    }

    /**
     * Add custom parameters to the OAuth2 authorization request
     * - prompt=select_account: Forces account selection on every login
     * - access_type=offline: (Optional) Request refresh token from Google
     */
    private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
        Map<String, Object> additionalParameters = new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
        
        // Force Google to show account selection screen
        additionalParameters.put("prompt", "select_account");
        
        // Optional: Request offline access for refresh tokens (if needed in future)
        // additionalParameters.put("access_type", "offline");
        
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }
}
