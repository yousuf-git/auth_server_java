package com.learning.security.utils;
import java.util.Date;

import javax.crypto.SecretKey;

import com.learning.security.exceptions.CustomJwtException;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.learning.security.services.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;

/**
 * <h2>JwtUtils</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This utility class provides methods for generating, validating, and parsing JWT tokens.<br>
 * </p>
 * <ul>
 *   <li>Handles all JWT operations such as token creation, signature verification, and extracting claims.</li>
 *   <li>Centralizes JWT logic for use by authentication filters and controllers.</li>
 *   <li>Access tokens are short-lived (5 minutes) for security</li>
 *   <li>Use with refresh tokens for long-lived sessions</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Called by authentication filters and controllers during login, request validation, and user authentication.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>Tokens are generated for authenticated users, validated for incoming requests, and claims are extracted for authorization.</li>
 * </ul>
 */
@Component
public class JwtUtils {

    @Value("${yousuf.app.jwtSecret}")
    private String jwtSecret;

    @Value("${yousuf.app.jwtExpirationTimeInMs}")
    private int jwtExpirationTimeInMs;

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
    
    /**
     * Get JWT expiration time in milliseconds
     */
    public long getJwtExpirationMs() {
        return jwtExpirationTimeInMs;
    }
    
    /**
     * <h3>generateTokenByAuth</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Generates a short-lived JWT access token (5 minutes) for an authenticated user.<br>
     * </p>
     * <ul>
     *   <li>Uses user details from the authentication object to set claims and expiration.</li>
     *   <li>Signs the token with a secret key.</li>
     *   <li>Short expiration enhances security - use with refresh tokens</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>After successful authentication during login or token refresh.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The generated token is sent to the client for use in subsequent requests.</li>
     *   <li>Client should refresh token before expiration using refresh token.</li>
     * </ul>
     * @param auth the Authentication object containing user details
     * @return the generated JWT token as a String
     */
    public String generateTokenByAuth(Authentication auth) {
        
        // Only valid authentication object should reach here
        UserDetailsImpl userDetails = (UserDetailsImpl) auth.getPrincipal();

        // https://github.com/jwtk/jjwt?tab=readme-ov-file#creating-a-jwt
        return Jwts.builder()
                .header().add("typ", "JWT")
                .and()
                .issuer("M. Yousuf")
                .subject(userDetails.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationTimeInMs))
                .signWith(getKey(), Jwts.SIG.HS256)
                .compact();
        

        // It is usually recommended to specify the signing key by calling the JwtBuilder's signWith method and let JJWT determine the most secure algorithm allowed for the specified key.
                // .signWith(getKey())
            // .compact();
    }

    private SecretKey getKey() {
        // SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
        // logger.info("Key: {}", key);
        // logger.info("Length: {}", Decoders.BASE64.decode(jwtSecret).length);
        // return key;
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * <h3>validateJwt</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Validates the provided JWT token for structure, signature, and expiration.<br>
     * </p>
     * <ul>
     *   <li>Throws a <code>CustomJwtException</code> if the token is invalid, expired, or malformed.</li>
     *   <li>Returns true if the token is valid.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>During request filtering to ensure the token is valid before authentication.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>If valid, authentication proceeds; if not, error handling is triggered.</li>
     * </ul>
     * @param jwtToken the JWT token to validate
     * @return true if valid, otherwise throws exception
     */
    public boolean validateJwt(String jwtToken) {
        logger.debug("jwtToken: {}", jwtToken);
        try {
            Jwts.parser()
                .verifyWith(getKey())
                .build().parseSignedClaims(jwtToken);
            return true;
            // Handling the exceptions that can be thrown by parse()
            /*
             * 1. MalformedJwtException - if the specified JWT was incorrectly constructed 
             * 2. SignatureException - if a JWS signature was discovered, but could not be verified. 
             * 3. SecurityException - if the specified JWT string is a JWE and decryption fails
             * 4. ExpiredJwtException - if the specified JWT is a Claims JWT and the Claims has an expiration time before the time this method is invoked.
             * 5. IllegalArgumentException - if the specified string is null or empty or only whitespace.
             */
        } catch (MalformedJwtException e) {
            logger.error("JWT was incorrectly constructed: {}", e.getMessage());
            throw new CustomJwtException("JWT was incorrectly constructed: " + e.getMessage(), HttpServletResponse.SC_BAD_REQUEST);
        } catch (SignatureException e) {
            logger.error("JWS signature was discovered, but could not be verified: {}", e.getMessage());
            throw new CustomJwtException("Invalid token signature", HttpServletResponse.SC_UNAUTHORIZED);
        } catch (SecurityException e) {
            logger.error("JWT string is a JWE and decryption fails: {}", e.getMessage());
            throw new CustomJwtException("JWT string is a JWE and decryption failed", HttpServletResponse.SC_BAD_REQUEST);
        } catch (ExpiredJwtException e) {
            logger.error("Token is expired: {}", e.getMessage());
            throw new CustomJwtException("Token expired: " + e.getMessage(),  HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            logger.error("Token is null or empty or only whitespace: {}", e.getMessage());
            throw new CustomJwtException("Token is missing or invalid", HttpServletResponse.SC_BAD_REQUEST);
        }
//        return false;

         
    }

    /**
     * <h3>getUsernameFromJwtToken</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Extracts the username (subject) from the provided JWT token.<br>
     * </p>
     * <ul>
     *   <li>Parses the token and retrieves the subject claim.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>After token validation, to identify the user making the request.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The username is used to load user details and set authentication context.</li>
     * </ul>
     * @param jwtToken the JWT token
     * @return the username (subject) from the token
     */
    public String getUsernameFromJwtToken(String jwtToken) {
//      Steps   Build - Get claims - get subject (I've set username as subject)

        return Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(jwtToken)
                    .getPayload().getSubject();
                    // .getHeader().get("Subject");
    }
}
