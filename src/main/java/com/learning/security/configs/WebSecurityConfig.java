package com.learning.security.configs;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.learning.security.auth.AuthEntryPointJwt;
import com.learning.security.auth.AuthTokenFilter;
import com.learning.security.auth.JwtAccessDeniedHandler;
import com.learning.security.auth.OAuth2AuthenticationFailureHandler;
import com.learning.security.auth.OAuth2AuthenticationSuccessHandler;
import com.learning.security.services.CustomOAuth2UserService;
import com.learning.security.services.UserDetailsServiceImpl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <h2>WebSecurityConfig</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class configures the security settings for the Spring Boot application.<br>
 * </p>
 * <ul>
 *   <li>Defines beans for authentication, password encoding, and security filter chain.</li>
 *   <li>Sets up which endpoints are secured and which are publicly accessible.</li>
 *   <li>Configures exception handling for authentication and authorization errors.</li>
 *   <li>Integrates custom JWT authentication and access denied handlers.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Loaded at application startup to set up Spring Security's behavior for all HTTP requests.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>All incoming requests are filtered and authorized according to these rules.</li>
 *   <li>Custom handlers are invoked for authentication and authorization failures.</li>
 * </ul>
 */
@Configuration
// @EnableWebSecurity
@EnableMethodSecurity
public class WebSecurityConfig {

    @Autowired
    UserDetailsServiceImpl userDetailsServiceImpl;

    // @Autowired
    // JwtUtils jwtUtils;
    
    /**
     * <h3>getAuthTokenFilter</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Provides a bean for the custom JWT authentication filter.<br>
     * </p>
     * <ul>
     *   <li>Used to intercept and validate JWT tokens in requests.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring when building the security filter chain.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The filter is added to the security filter chain.</li>
     * </ul>
     * @return AuthTokenFilter instance
     */
    @Bean
    public AuthTokenFilter getAuthTokenFilter() {
        return new AuthTokenFilter();
        // return new AuthTokenFilter(jwtUtils);
    }

    /**
     * <h3>getAuthProvider</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Provides a bean for the authentication provider using DAO and password encoder.<br>
     * </p>
     * <ul>
     *   <li>Handles authentication logic using user details and password encoding.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Used by Spring Security during authentication.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>Authentication provider is used to validate user credentials.</li>
     * </ul>
     * @return DaoAuthenticationProvider instance
     */
    @Bean
    public DaoAuthenticationProvider getAuthProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();

        // Setting password encoder in auth provider
        authProvider.setPasswordEncoder(passwordEncoder());
        // Setting user details service in auth provider
        authProvider.setUserDetailsService(userDetailsServiceImpl);

        return authProvider;
    }

    /**
     * <h3>passwordEncoder</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Provides a bean for password encoding using BCrypt.<br>
     * </p>
     * <ul>
     *   <li>Ensures passwords are securely hashed and compared.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Used by authentication provider and user service.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>Passwords are encoded and validated securely.</li>
     * </ul>
     * @return PasswordEncoder instance
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * <h3>getAuthManager</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Provides a bean for the authentication manager.<br>
     * </p>
     * <ul>
     *   <li>Coordinates authentication process across providers.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Used by Spring Security during authentication.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>Authentication manager is used to authenticate user credentials.</li>
     * </ul>
     * @param authConfig AuthenticationConfiguration instance
     * @return AuthenticationManager instance
     * @throws Exception if authentication manager creation fails
     */
    @Bean
    public AuthenticationManager getAuthManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Autowired
    AuthEntryPointJwt authEntryPointJwt;
    @Autowired
    JwtAccessDeniedHandler accessDeniedHandler;
    @Autowired
    CustomOAuth2UserService customOAuth2UserService;
    @Autowired
    OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    @Autowired
    OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    
    /**
     * <h3>getFilterChain</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Configures the main security filter chain for HTTP requests.<br>
     * </p>
     * <ul>
     *   <li>Sets up CSRF, session management, exception handling, and endpoint authorization.</li>
     *   <li>Adds custom authentication and access denied handlers.</li>
     *   <li>Registers the JWT authentication filter before the username/password filter.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring at application startup.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>All HTTP requests are processed according to these security rules.</li>
     * </ul>
     * @param http the HttpSecurity object to configure
     * @return the configured SecurityFilterChain
     * @throws Exception if configuration fails
     */
    @Bean
    SecurityFilterChain getFilterChain(HttpSecurity http) throws Exception {
        
        http.csrf(csrf -> csrf.disable())
            .exceptionHandling((e) -> {
                    e.authenticationEntryPoint(authEntryPointJwt);
                    e.accessDeniedHandler(accessDeniedHandler);
                })
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/auth/**").permitAll()
                    .requestMatchers("/oauth2/**").permitAll()
                    .requestMatchers("/login/**").permitAll()
                    .requestMatchers("/test/all/**").permitAll()
                    .requestMatchers("/greet/**").permitAll()
                    .requestMatchers("/actuator/**").permitAll()
                    .requestMatchers("/error").permitAll()
                    // Static resources - Allow all HTML files and static assets
                    .requestMatchers("/*.html", "/static/**", "/css/**", "/js/**", "/images/**").permitAll()
                    // For swagger docs - updated paths to include swagger-ui.html
                    .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/v2/api-docs/**", "/swagger-resources/**", "/webjars/**").permitAll()
                    .anyRequest().authenticated();
            })
            // OAuth2 Login Configuration
            .oauth2Login(oauth2 -> oauth2
                .authorizationEndpoint(authorization -> authorization
                    .baseUri("/oauth2/authorize"))
                .redirectionEndpoint(redirection -> redirection
                    .baseUri("/login/oauth2/code/*"))
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService))
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
            
            http.authenticationProvider(getAuthProvider());
            http.addFilterBefore(getAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }

    
}

/*
 * For CORS config

@Configuration
@EnableWebMvc
public class WebConfig extends WebMvcConfigurerAdapter {
    @Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/api/**")
			.allowedOrigins("http://domain2.com")
			.allowedMethods("PUT", "DELETE")
			.allowedHeaders("header1", "header2", "header3")
			.exposedHeaders("header1", "header2")
			.allowCredentials(false).maxAge(3600);
	}
}

*/