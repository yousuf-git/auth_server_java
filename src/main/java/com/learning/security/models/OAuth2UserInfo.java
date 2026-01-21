package com.learning.security.models;

import java.util.Map;

/**
 * <h2>OAuth2UserInfo</h2>
 * <p>
 * Abstract class for extracting user information from OAuth2 providers (Google, GitHub, etc.)
 * </p>
 */
public abstract class OAuth2UserInfo {
    protected Map<String, Object> attributes;

    public OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public abstract String getId();

    public abstract String getName();

    public abstract String getEmail();

    public abstract String getImageUrl();
}
