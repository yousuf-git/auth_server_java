package com.learning.security.utils;

import com.learning.security.services.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    @Value("${yousuf.app.cookie.secure:false}")
    private boolean secureCookie;

    @Value("${yousuf.app.refreshTokenExpirationTimeInMs:604800000}")
    private long refreshTokenDurationMs;

    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setPath("/");
        cookie.setMaxAge((int) (refreshTokenDurationMs / 1000));
        cookie.setAttribute("SameSite", "Lax");
        response.addCookie(cookie);
    }

    public void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(secureCookie);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * Get the hash of the current refresh token from cookie.
     * Uses RefreshTokenService.hashToken for consistent hashing.
     */
    public String getCurrentTokenHash(HttpServletRequest request) {
        String token = getRefreshTokenFromCookie(request);
        if (token != null) {
            return RefreshTokenService.hashToken(token);
        }
        return null;
    }
}
