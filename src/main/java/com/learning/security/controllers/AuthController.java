// Auth Controller

package com.learning.security.controllers;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.learning.security.dtos.LoginRequest;
import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.SignUpRequest;
import com.learning.security.dtos.TokenPair;
import com.learning.security.enums.AuthProvider;
import com.learning.security.enums.RevocationReason;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.payload.response.AuthResponse;
import com.learning.security.repos.RoleRepo;
import com.learning.security.repos.UserRepo;
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.JwtUtils;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", maxAge = 3600, allowCredentials = "true") // Allow credentials for cookies, maxAge is in seconds; 3600s = 1 hr
/*
 * The HTTP Access-Control-Max-Age response header indicates how long the
 * results of a preflight request (that is, the information contained in the
 * Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be
 * cached.
 */
// https://docs.spring.io/spring-framework/docs/4.2.x/spring-framework-reference/html/cors.html
public class AuthController {

    @Autowired
    UserRepo userRepo;

    @Autowired
    PasswordEncoder encoder;
    // Will automatically find its implemenation from <code>WebSecurityConfig<code>
    // which is BCryptPasswordEncoder

    @Autowired
    RoleRepo roleRepo;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignUpRequest request,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        // Check if user already exists - by email
        if (userRepo.existsByEmail(request.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("Email already exists !"), HttpStatus.BAD_REQUEST);
        }

        // If not - Build a new user
        User user = new User();
        //
        /*
         * --------------- <code>User<code> requires ---------------
         * String email
         * String password - first encode and then attach with user
         * Role role
         */
        // Trying to grab the role from request and set it to user
        if (!setRole(user, request.getRole())) {
            return new ResponseEntity<>(new ResponseMessage("No Valid role found in the request !"),
                    HttpStatus.BAD_REQUEST);
        }
        user.setEmail(request.getEmail());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setProvider(AuthProvider.LOCAL);

        User savedUser = userRepo.save(user);

        // After successful signup, authenticate and create tokens
        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate access token (short duration)
            String accessToken = jwtUtils.generateTokenByAuth(authentication);
            
            // Generate refresh token (long duration) and set in secure cookie
            TokenPair tokenPair = refreshTokenService.createRefreshToken(savedUser, httpRequest, null);
            setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            // Get user details
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

            // Return access token in response body
            AuthResponse authResponse = new AuthResponse(
                accessToken,
                userDetails.getId(),
                userDetails.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.CREATED);
            
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseMessage("User created but authentication failed"));
        }
    }

    /**
     * 
     * @param user        User object to which role is to be attached
     * @param roleFromReq Role name from the request
     * @return false if no valid role found, true otherwise
     * @apiNote All defined Roles Must exist in the DB already
     */

    private boolean setRole(User user, String roleFromReq) {

        // Default Role - CUSTOMER
        if (roleFromReq == null || roleFromReq.isEmpty()) {
            Role userRole = roleRepo.findByName("ROLE_CUSTOMER")
                    .orElseThrow(() -> new RuntimeException("Error: Role not found in DB."));
            user.setRole(userRole);
            return true;
        }

        // Map request string to actual role name
        String roleName = "";
        if (!(roleFromReq.equals("ROLE_CUSTOMER") ||
                roleFromReq.equals("ROLE_ADMIN") ||
                roleFromReq.equals("ROLE_PLANT_MANAGER"))

        ) {
            switch (roleFromReq.toLowerCase()) {
                case "user":
                case "customer":
                    roleName = "ROLE_CUSTOMER";
                    break;
                case "admin":
                    roleName = "ROLE_ADMIN";
                    break;
                case "mod":
                case "manager":
                case "plant_manager":
                    roleName = "ROLE_PLANT_MANAGER";
                    break;
                default:
                    return false; // Invalid role
            }
        } else {
            roleName = roleFromReq;
        }

        Role role = roleRepo.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Error: Role not found in DB."));
        user.setRole(role);
        return true;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@Valid @RequestBody LoginRequest loginRequest,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        try {
            // Authenticating the user using AuthenticationManager
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            // UsernamePasswordAuthenticationToken extends AbstractAuthenticationToken which
            // implements Authentication

            // Throws: AuthenticationException - if authentication fails

            // Setting in the security context holder
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate short-lived access token (5 minutes)
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            // Get user details
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            
            // Generate long-lived refresh token (7 days) and set in secure cookie
            TokenPair tokenPair = refreshTokenService.createRefreshToken(
                userRepo.findById(userDetails.getId()).orElseThrow(), 
                httpRequest, 
                null
            );
            setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

            // Return access token in response body (NOT redirecting)
            AuthResponse authResponse = new AuthResponse(
                accessToken,
                userDetails.getId(),
                userDetails.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.OK);
            
        } catch (LockedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ResponseMessage("Account is locked. Please contact administrator."));
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid email or password"));
        }
    }

    /**
     * Refresh access token using refresh token from cookie
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get refresh token from cookie
            String refreshToken = getRefreshTokenFromCookie(request);
            
            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ResponseMessage("Refresh token not found"));
            }

            // Rotate refresh token (validates and creates new one)
            TokenPair tokenPair = refreshTokenService.rotateRefreshToken(refreshToken, request);
            
            // Set new refresh token in cookie
            setRefreshTokenCookie(response, tokenPair.getRawToken());

            // Generate new access token
            User user = tokenPair.getRefreshToken().getUser();
            Authentication authentication = createAuthenticationFromUser(user);
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            // Get role
            String role = user.getRole() != null ? user.getRole().getName() : "";

            // Return new access token
            AuthResponse authResponse = new AuthResponse(
                accessToken,
                user.getId(),
                user.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.OK);
            
        } catch (Exception e) {
            // Token invalid, expired, or theft detected
            clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage(e.getMessage()));
        }
    }

    /**
     * Logout - revoke refresh token
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = getRefreshTokenFromCookie(request);
            
            if (refreshToken != null) {
                refreshTokenService.revokeRefreshToken(refreshToken, RevocationReason.MANUAL_LOGOUT);
            }
            
            clearRefreshTokenCookie(response);
            
            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));
            
        } catch (Exception e) {
            clearRefreshTokenCookie(response);
            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));
        }
    }

    /**
     * Logout from all devices - revoke all user tokens
     */
    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = getRefreshTokenFromCookie(request);
            
            if (refreshToken != null) {
                User user = refreshTokenService.getUserFromRefreshToken(refreshToken);
                refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.MANUAL_LOGOUT);
            }
            
            clearRefreshTokenCookie(response);
            
            return ResponseEntity.ok(new ResponseMessage("Logged out from all devices"));
            
        } catch (Exception e) {
            clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid session"));
        }
    }

    // ========== Helper Methods ==========

    // Refresh token expiry time from application.yml
    @Value("${yousuf.app.refreshTokenExpirationTimeInMs:604800000}") // 7 days default
    private Long refreshTokenDurationMs;


    /**
     * Set refresh token in secure HttpOnly cookie
     */
    private void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie("refreshToken", refreshToken);
        cookie.setHttpOnly(true);  // Prevent JavaScript access
        cookie.setSecure(false);    // Set to true in production with HTTPS
        cookie.setPath("/");
        cookie.setMaxAge((int)(refreshTokenDurationMs / 1000));
        cookie.setAttribute("SameSite", "Lax"); // CSRF protection
        response.addCookie(cookie);
    }

    /**
     * Get refresh token from cookie
     */
    private String getRefreshTokenFromCookie(HttpServletRequest request) {
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
     * Clear refresh token cookie
     */
    private void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("refreshToken", "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // Set to true in production
        cookie.setPath("/");
        cookie.setMaxAge(0); // Delete cookie
        response.addCookie(cookie);
    }

    /**
     * Create Authentication object from User entity
     */
    private Authentication createAuthenticationFromUser(User user) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        return new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        );
    }

}
