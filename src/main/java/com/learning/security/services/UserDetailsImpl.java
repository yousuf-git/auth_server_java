package com.learning.security.services;

import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.learning.security.models.User;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * <h2>UserDetailsImpl</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class is a custom implementation of Spring Security's <code>UserDetails</code> interface.<br>
 * It represents the authenticated user's principal and authorities. Helps to work with Spring Security and Authentication object later<br>
 * </p>
 * <ul>
 *   <li>Encapsulates user information (id, username, email, password, active status, and roles).</li>
 *   <li>Converts application-specific <code>User</code> model into a format understood by Spring Security.</li>
 *   <li>Used by the authentication system to check credentials and grant authorities.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Created by the <code>UserDetailsServiceImpl</code> when loading a user from the database.</li>
 *   <li>Injected into the security context after successful authentication.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>Spring Security uses this object to check user permissions and manage authentication state.</li>
 * </ul>
 */

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails, OAuth2User {

    @Serial
    private static final long serialVersionUID = 1L;    // It is used to ensure that the class sending the object is the same as the class receiving the object.

    private Integer id;
    private String  username;
    private String  email;
    private String  password;
    private boolean active;
    private boolean isLocked;
    private Map<String, Object> attributes;

    /** <h3>roles</h3>
     * You may notice that {@link com.learning.security.models.User User} has <code>roles</code> as <code>Set</code> but I've used {@code List<GrantedAuthority>} here.
     * It is important to work with Spring Security and Authentication object later.
     * <p>
     * GrantedAuthority is an interface that represents an authority granted to an Authentication object.
     * It is used to define the authorities granted to users.

     * We have SimpleGrantedAuthority class that implements GrantedAuthority interface.
     */
    private List<GrantedAuthority> roles;


    /**
     * <h3>build</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Static factory method to convert a <code>User</code> entity into a <code>UserDetailsImpl</code> object.<br>
     * </p>
     * <ul>
     *   <li>Extracts roles and converts them to <code>GrantedAuthority</code> list.</li>
     *   <li>Populates all required fields for Spring Security.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Called by <code>UserDetailsServiceImpl</code> when loading user details from the database.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The returned object is used for authentication and authorization checks.</li>
     * </ul>
     * @param user the application User entity
     * @return a UserDetailsImpl object for Spring Security
     */
    public static UserDetailsImpl build(User user) {
    
    // Get the role of user and convert it into List<GrantedAuthority>
    List<GrantedAuthority> authorities = List.of(
        new SimpleGrantedAuthority(user.getRole().getName())
    );

    return new UserDetailsImpl(
        user.getId(), 
        user.getEmail(), 
        user.getEmail(),
        user.getPassword(),
        true,
        user.getIsLocked() != null ? user.getIsLocked() : false,
        null,
        authorities);
    }

    /**
     * <h3>build with OAuth2 attributes</h3>
     * <p>
     * Static factory method to convert a User entity with OAuth2 attributes into a UserDetailsImpl object.
     * </p>
     * @param user the application User entity
     * @param attributes OAuth2 user attributes
     * @return a UserDetailsImpl object for Spring Security with OAuth2 support
     */
    public static UserDetailsImpl build(User user, Map<String, Object> attributes) {
        UserDetailsImpl userDetails = build(user);
        userDetails.setAttributes(attributes);
        return userDetails;
    }

    /**
     * <h3>getAuthorities</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Returns the authorities granted to the user.<br>
     * </p>
     * <ul>
     *   <li>Used by Spring Security to check user permissions.</li>
     * </ul>
     * @return collection of granted authorities
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }
    @Override
    public boolean isEnabled() {
        return active;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return active;
    }

    // OAuth2User interface methods
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return email;
    }
}


