package com.learning.security.auth;
import com.learning.security.exceptions.CustomJwtException;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.learning.security.services.UserDetailsServiceImpl;
import com.learning.security.utils.JwtUtils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * <h2>AuthTokenFilter</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class is a custom filter that extends <code>OncePerRequestFilter</code> to handle JWT authentication for each HTTP request.<br>
 * </p>
 * <ul>
 *   <li>Extracts the JWT token from the Authorization header of incoming requests.</li>
 *   <li>Validates the token and, if valid, loads user details and sets the authentication in the Spring Security context.</li>
 *   <li>If the token is invalid or expired, it stores the exception for further handling (e.g., by <code>AuthEntryPointJwt</code>).</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Automatically invoked by Spring Security for every request before it reaches the controller, as part of the filter chain.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>If authentication is successful, the user's details are available in the security context for the rest of the request.</li>
 *   <li>If authentication fails, the request proceeds but with no authentication set, and errors are handled downstream.</li>
 * </ul>
 */
// @Component
public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	JwtUtils jwtUtils;

	// private final JwtUtils jwtUtils;

    // Constructor injection
    // @Autowired
	// public AuthTokenFilter(JwtUtils jwtUtils) {
    //     this.jwtUtils = jwtUtils;
    // }

	@Autowired
	UserDetailsServiceImpl userDetailsServiceImpl;

	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	/**
	 * <h3>doFilterInternal</h3>
	 * <p>
	 * <b>Purpose:</b><br>
	 * Processes each HTTP request to check for a JWT token, validate it, and set authentication if valid.<br>
	 * </p>
	 * <ul>
	 *   <li>Extracts the JWT from the Authorization header.</li>
	 *   <li>Validates the token using <code>JwtUtils</code>.</li>
	 *   <li>If valid, loads user details and sets authentication in the security context.</li>
	 *   <li>If invalid, stores the exception for error handling.</li>
	 * </ul>
	 * <p><b>When is it called?</b></p>
	 * <ul>
	 *   <li>Automatically by the Spring Security filter chain for every request.</li>
	 * </ul>
	 * <p><b>What happens after?</b></p>
	 * <ul>
	 *   <li>If authentication is set, the user is considered authenticated for the rest of the request.</li>
	 *   <li>Otherwise, the request continues unauthenticated and may be rejected by later security checks.</li>
	 * </ul>
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param filterChain the filter chain to pass the request/response to the next filter
	 * @throws ServletException if an error occurs during the filter process
	 * @throws IOException if an I/O error occurs
	 */
	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain filterChain) throws ServletException, IOException {
			
		try {
			// Skip JWT processing for public endpoints
			String path = request.getRequestURI();
			if (path.startsWith("/actuator") || path.startsWith("/auth") || path.startsWith("/test/all") ||
					path.startsWith("/greet") || path.startsWith("/swagger-ui") || path.startsWith("/v3/api-docs") ||
					path.startsWith("/oauth2") || path.startsWith("/login") || path.equals("/error") || path.endsWith(".html") || 
					path.startsWith("/static") || path.startsWith("/css") || path.startsWith("/js") || path.startsWith("/images")) {
				filterChain.doFilter(request, response);
				return;
			}

			String jwtToken = parseJwtFromRequest(request);
		
			if (jwtToken != null && jwtUtils.validateJwt(jwtToken)) {
				String username = jwtUtils.getUsernameFromJwtToken(jwtToken);

				UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);

				// Setting the current UserDetails in SecurityContext using
				// https://docs.spring.io/spring-security/reference/servlet/authentication/architecture.html#servlet-authentication-securitycontext

				UsernamePasswordAuthenticationToken authentication =
				new UsernamePasswordAuthenticationToken(
						userDetails,                        // principal
						null,                   // password
						userDetails.getAuthorities());      // GrantedAuthorities

				/*
				 *  Setting additional details about the authentication process
				 *  (such as the IP address and session ID) to the authentication object.
				 *  new WebAuthenticationDetailsSource().buildDetails(request) extracts these details from the current HTTP request and attaches them to the authentication object.
				 *  Essentially, it enriches the authentication object with request-specific information.
				 */
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

				SecurityContextHolder.getContext().setAuthentication(authentication);
				/*
				 * After this, everytime you want to get UserDetails, just use SecurityContext like this:
				 * UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
				 * And you can get the username, password and authorities like this:
				 * userDetails.getUsername()
				 * userDetails.getPassword()
				 * userDetails.getAuthorities()
				*/

			}
		} catch (CustomJwtException e) {
			// Store the custom exception in request attribute
			request.setAttribute("jwt.exception", e);
			logger.error("JWT validation failed: {}", e.getMessage());
		} catch (Exception e) {
			logger.error("Cannot set user Authentication: {}", e.getMessage());
		}

		// Pass the request to next filter
		filterChain.doFilter(request, response);
			
	}

	/**
	 * <h3>parseJwtFromRequest</h3>
	 * <p>
	 * <b>Purpose:</b><br>
	 * Extracts the JWT token from the Authorization header of the HTTP request.<br>
	 * </p>
	 * <ul>
	 *   <li>Checks if the Authorization header is present and starts with "Bearer ".</li>
	 *   <li>Returns the token part if present, otherwise returns null.</li>
	 * </ul>
	 * <p><b>When is it called?</b></p>
	 * <ul>
	 *   <li>Internally by <code>doFilterInternal</code> for every request.</li>
	 * </ul>
	 * <p><b>What happens after?</b></p>
	 * <ul>
	 *   <li>The extracted token is validated and used for authentication if present.</li>
	 * </ul>
	 * @param request the HTTP request
	 * @return the JWT token string or null if not present
	 */
	private String parseJwtFromRequest(HttpServletRequest request) {
		String authHeader = request.getHeader("Authorization");

		/*
		 * Sample
		 * Authorization: Bearer 
		 */

		if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
				
			// Skipping "Bearer " and grab the actual token
			return authHeader.substring(7);
		}
		return null;
	}

}
