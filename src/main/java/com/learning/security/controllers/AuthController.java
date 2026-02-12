package com.learning.security.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
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
import com.learning.security.services.RefreshTokenService;
import com.learning.security.services.RoleService;
import com.learning.security.services.UserService;
import com.learning.security.services.UserDetailsImpl;
import com.learning.security.utils.CookieUtils;
import com.learning.security.utils.JwtUtils;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
// @CrossOrigin(originPatterns = "*", maxAge = 3600, allowCredentials = "true") // Allow credentials for cookies, maxAge is in seconds; 3600s = 1 hr
/*
 * The HTTP Access-Control-Max-Age response header indicates how long the
 * results of a preflight request (that is, the information contained in the
 * Access-Control-Allow-Methods and Access-Control-Allow-Headers headers) can be
 * cached.
 */
// https://docs.spring.io/spring-framework/docs/4.2.x/spring-framework-reference/html/cors.html
public class AuthController {

    @Autowired
    UserService userService;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    RoleService roleService;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    CookieUtils cookieUtils;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignUpRequest request,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        if (userService.existsByEmail(request.getEmail())) {
            return new ResponseEntity<>(new ResponseMessage("Email already exists !"), HttpStatus.BAD_REQUEST);
        }

        User user = new User();
        if (!setRole(user, request.getRole())) {
            return new ResponseEntity<>(new ResponseMessage("No Valid role found in the request !"),
                    HttpStatus.BAD_REQUEST);
        }
        user.setEmail(request.getEmail());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setProvider(AuthProvider.LOCAL);

        User savedUser = userService.save(user);

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            TokenPair tokenPair = refreshTokenService.createRefreshToken(savedUser, httpRequest, null);
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

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

    private boolean setRole(User user, String roleFromReq) {
        if (roleFromReq == null || roleFromReq.isEmpty()) {
            Role userRole = roleService.findByName("ROLE_CUSTOMER")
                    .orElseThrow(() -> new RuntimeException("Error: Role not found in DB."));
            user.setRole(userRole);
            return true;
        }

        String roleName = "";
        if (!(roleFromReq.equals("ROLE_CUSTOMER") ||
                roleFromReq.equals("ROLE_ADMIN") ||
                roleFromReq.equals("ROLE_PLANT_MANAGER"))) {
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
                    return false;
            }
        } else {
            roleName = roleFromReq;
        }

        Role role = roleService.findByName(roleName)
                .orElseThrow(() -> new RuntimeException("Error: Role not found in DB."));
        user.setRole(role);
        return true;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signin(@Valid @RequestBody LoginRequest loginRequest,
                                    HttpServletRequest httpRequest,
                                    HttpServletResponse httpResponse) {

        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            TokenPair tokenPair = refreshTokenService.createRefreshToken(
                userService.findById(userDetails.getId()).orElseThrow(),
                httpRequest,
                null
            );
            cookieUtils.setRefreshTokenCookie(httpResponse, tokenPair.getRawToken());

            String role = userDetails.getRoles().isEmpty() ? "" : userDetails.getRoles().get(0).getAuthority();

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

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ResponseMessage("Refresh token not found"));
            }

            // Rotate refresh token (validates and creates new one)
            TokenPair tokenPair = refreshTokenService.rotateRefreshToken(refreshToken, request);

            cookieUtils.setRefreshTokenCookie(response, tokenPair.getRawToken());

            User user = tokenPair.getRefreshToken().getUser();
            Authentication authentication = createAuthenticationFromUser(user);
            String accessToken = jwtUtils.generateTokenByAuth(authentication);

            String role = user.getRole() != null ? user.getRole().getName() : "";

            AuthResponse authResponse = new AuthResponse(
                accessToken,
                user.getId(),
                user.getEmail(),
                role,
                jwtUtils.getJwtExpirationMs()
            );

            return new ResponseEntity<>(authResponse, HttpStatus.OK);

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            // Token invalid, expired, or theft detected
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Session expired. Please login again."));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken != null) {
                refreshTokenService.revokeRefreshToken(refreshToken, RevocationReason.MANUAL_LOGOUT);
            }

            cookieUtils.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.ok(new ResponseMessage("Logged out successfully"));
        }
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(HttpServletRequest request, HttpServletResponse response) {
        try {
            String refreshToken = cookieUtils.getRefreshTokenFromCookie(request);

            if (refreshToken != null) {
                User user = refreshTokenService.getUserFromRefreshToken(refreshToken);
                refreshTokenService.revokeAllUserTokens(user.getId(), RevocationReason.MANUAL_LOGOUT);
            }

            cookieUtils.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(new ResponseMessage("Logged out from all devices"));

        } catch (Exception e) {
            cookieUtils.clearRefreshTokenCookie(response);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseMessage("Invalid session"));
        }
    }

    /**
     * Creates Authentication object from User entity
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
