package com.learning.security.configs;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.learning.security.auth.AuthEntryPointJwt;
import com.learning.security.auth.AuthTokenFilter;
import com.learning.security.auth.JwtAccessDeniedHandler;
import com.learning.security.auth.OAuth2AuthenticationFailureHandler;
import com.learning.security.auth.OAuth2AuthenticationSuccessHandler;
import com.learning.security.services.CustomOAuth2UserService;
import com.learning.security.services.UserDetailsServiceImpl;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
@EnableMethodSecurity
public class WebSecurityConfig {

    @Autowired
    UserDetailsServiceImpl userDetailsServiceImpl;

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
        authProvider.setPasswordEncoder(passwordEncoder());
        authProvider.setUserDetailsService(userDetailsServiceImpl);
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager getAuthManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Autowired
    RateLimitFilter rateLimitFilter;
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

    @Value("${yousuf.app.cors.allowed-origins:http://localhost:3000,http://localhost:8080}")
    private String[] allowedOrigins;



    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(allowedOrigins));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
    
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

        http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers
                .contentTypeOptions(Customizer.withDefaults())
                .frameOptions(frame -> frame.deny())
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000))
            )
            .exceptionHandling(e -> {
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
                    .requestMatchers("/*.html", "/static/**", "/css/**", "/js/**", "/images/**").permitAll()
                    .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/v2/api-docs/**", "/swagger-resources/**", "/webjars/**").permitAll()
                    .anyRequest().authenticated();
            })
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
            http.addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class);
            http.addFilterBefore(getAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
