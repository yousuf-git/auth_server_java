package com.learning.security.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Optional;

/**
 * <h2>OAuth2CookieUtils</h2>
 * <p>
 * Utility for managing OAuth2 redirect URIs through cookies during the OAuth2 flow.
 * Stores redirect_uri and error_uri from client's initial request and retrieves them after authentication.
 * </p>
 */
@Component
public class OAuth2CookieUtils {

    public static final String REDIRECT_URI_PARAM = "redirect_uri";
    public static final String ERROR_URI_PARAM = "error_uri";
    private static final String OAUTH2_REDIRECT_URI_COOKIE = "oauth2_redirect_uri";
    private static final String OAUTH2_ERROR_URI_COOKIE = "oauth2_error_uri";
    private static final int COOKIE_EXPIRE_SECONDS = 180; // 3 minutes

    /**
     * Store redirect URI in cookie for later retrieval
     */
    public void addRedirectUriCookie(HttpServletResponse response, String redirectUri) {
        addCookie(response, OAUTH2_REDIRECT_URI_COOKIE, redirectUri, COOKIE_EXPIRE_SECONDS);
    }

    /**
     * Store error URI in cookie for later retrieval
     */
    public void addErrorUriCookie(HttpServletResponse response, String errorUri) {
        addCookie(response, OAUTH2_ERROR_URI_COOKIE, errorUri, COOKIE_EXPIRE_SECONDS);
    }

    /**
     * Get redirect URI from cookie
     */
    public Optional<String> getRedirectUriCookie(HttpServletRequest request) {
        return getCookie(request, OAUTH2_REDIRECT_URI_COOKIE);
    }

    /**
     * Get error URI from cookie
     */
    public Optional<String> getErrorUriCookie(HttpServletRequest request) {
        return getCookie(request, OAUTH2_ERROR_URI_COOKIE);
    }

    /**
     * Clear OAuth2 cookies
     */
    public void clearOAuth2Cookies(HttpServletRequest request, HttpServletResponse response) {
        deleteCookie(request, response, OAUTH2_REDIRECT_URI_COOKIE);
        deleteCookie(request, response, OAUTH2_ERROR_URI_COOKIE);
    }

    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(maxAge);
        cookie.setSecure(false); // Set to true in production with HTTPS
        response.addCookie(cookie);
    }

    private Optional<String> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            return Arrays.stream(cookies)
                    .filter(cookie -> cookie.getName().equals(name))
                    .map(Cookie::getValue)
                    .findFirst();
        }
        return Optional.empty();
    }

    private void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            Arrays.stream(cookies)
                    .filter(cookie -> cookie.getName().equals(name))
                    .forEach(cookie -> {
                        cookie.setValue("");
                        cookie.setPath("/");
                        cookie.setMaxAge(0);
                        response.addCookie(cookie);
                    });
        }
    }
}
