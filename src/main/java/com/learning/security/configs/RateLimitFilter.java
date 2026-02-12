package com.learning.security.configs;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitFilter.class);

    private static final int AUTH_LIMIT = 10;       // 10 requests per minute for signin/signup
    private static final int REFRESH_LIMIT = 20;    // 20 requests per minute for refresh
    private static final Duration WINDOW = Duration.ofMinutes(1);

    @Autowired(required = false)
    private StringRedisTemplate redisTemplate;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/auth/");
    }

    /**
     * Filters incoming HTTP requests to enforce rate limiting based on client IP and request path.
     * 
     * This method retrieves the request URI and client IP address, constructs a unique Redis key,
     * and increments a counter for that key. If the counter exceeds the predefined limit for the path
     * (higher for /auth/refresh endpoint), it responds with a 429 Too Many Requests status and blocks
     * the request. The counter is set to expire after a specified window. In case of Redis unavailability,
     * the filter logs a warning and allows the request to proceed (fail-open behavior).
     * 
     * @param request  the HttpServletRequest object containing the request details
     * @param response the HttpServletResponse object for sending the response
     * @param chain    the FilterChain to proceed with the request if not rate-limited
     * @throws ServletException if a servlet-related error occurs
     * @throws IOException      if an I/O error occurs during request processing
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        if (redisTemplate == null) {
            chain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String ip = getClientIp(request);
        String key = "rate_limit:" + ip + ":" + path;

        int limit = path.equals("/auth/refresh") ? REFRESH_LIMIT : AUTH_LIMIT;

        try {
            Long count = redisTemplate.opsForValue().increment(key);
            if (count != null && count == 1) {
                redisTemplate.expire(key, WINDOW); // Sets expiration/TTL only on first hit to avoid resetting the window on every request
            }

            if (count != null && count > limit) {
                logger.warn("Rate limit exceeded for IP: {} on path: {}", ip, path);
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setHeader("Retry-After", "60");
                response.getWriter().write("{\"message\":\"Too many requests. Please try again later.\"}");
                return;
            }
        } catch (Exception e) {
            // If Redis is unavailable, allow the request (fail-open)
            logger.warn("Rate limiting unavailable (Redis error): {}", e.getMessage());
        }

        chain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isEmpty()) {
            ip = ip.split(",")[0].trim(); // Take first IP from proxy chain
        }
        if (ip == null || ip.isEmpty()) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty()) {
            ip = request.getRemoteAddr();
        }
        return ip;
    }
}
