package com.learning.security.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.learning.security.repos.UserRepo;

import jakarta.transaction.Transactional;
/**
 * <h2>UserDetailsServiceImpl</h2>
 * <p>
 * <b>Purpose:</b><br>
 * This class implements Spring Security's <code>UserDetailsService</code> interface.<br>
 * It is responsible for retrieving user details from the database and converting them into a format understood by Spring Security.<br>
 * </p>
 * <ul>
 *   <li>Fetches user information using the application's <code>UserRepo</code>.</li>
 *   <li>Converts the user entity into a <code>UserDetailsImpl</code> object for authentication and authorization.</li>
 * </ul>
 * <p><b>When is it used?</b></p>
 * <ul>
 *   <li>Automatically called by Spring Security during the authentication process when a user attempts to log in.</li>
 * </ul>
 * <p><b>What happens after?</b></p>
 * <ul>
 *   <li>The returned <code>UserDetailsImpl</code> object is used by the authentication manager to verify credentials and set up the security context.</li>
 * </ul>
 */

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    /**
     * <h3>loadUserByUsername</h3>
     * <p>
     * <b>Purpose:</b><br>
     * Loads the user from the database by username and converts it to a <code>UserDetailsImpl</code> object.<br>
     * </p>
     * <ul>
     *   <li>Queries the database for a user with the given username.</li>
     *   <li>If found, converts the user entity to a <code>UserDetailsImpl</code> object.</li>
     *   <li>If not found, throws a <code>UsernameNotFoundException</code>.</li>
     * </ul>
     * <p><b>When is it called?</b></p>
     * <ul>
     *   <li>Automatically by Spring Security during authentication.</li>
     * </ul>
     * <p><b>What happens after?</b></p>
     * <ul>
     *   <li>The returned object is used for authentication and authorization checks.</li>
     * </ul>
     * @param username the username identifying the user whose data is required
     * @return a fully populated UserDetailsImpl object
     * @throws UsernameNotFoundException if the user could not be found
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepo.findByEmail(email)
            .map(UserDetailsImpl::build)
            .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + email));
    }

}
