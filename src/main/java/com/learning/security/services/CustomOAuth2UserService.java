package com.learning.security.services;

import com.learning.security.enums.AuthProvider;
import com.learning.security.exceptions.OAuth2AuthenticationProcessingException;
import com.learning.security.models.GoogleOAuth2UserInfo;
import com.learning.security.models.OAuth2UserInfo;
import com.learning.security.models.Role;
import com.learning.security.models.User;
import com.learning.security.repos.RoleRepo;
import com.learning.security.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Optional;

/**
 * <h2>CustomOAuth2UserService</h2>
 * <p>
 * Custom OAuth2 user service to load user from OAuth2 provider (Google)
 * and create/update user in the database
 * </p>
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private RoleRepo roleRepo;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            return processOAuth2User(userRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = getOAuth2UserInfo(
            userRequest.getClientRegistration().getRegistrationId(), 
            oAuth2User.getAttributes()
        );

        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepo.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        
        if (userOptional.isPresent()) {
            user = userOptional.get();
            AuthProvider provider = AuthProvider.valueOf(
                userRequest.getClientRegistration().getRegistrationId().toUpperCase()
            );
            
            if (!user.getProvider().equals(provider)) {
                throw new OAuth2AuthenticationProcessingException(
                    "Looks like you're signed up with " + user.getProvider() + 
                    " account. Please use your " + user.getProvider() + " account to login."
                );
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(userRequest, oAuth2UserInfo);
        }

        return UserDetailsImpl.build(user, oAuth2User.getAttributes()); // UserDetailsImpl implements OAuth2User that's why it can be returned here
    }

    private OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase("google")) {
            return new GoogleOAuth2UserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationProcessingException(
                "Sorry! Login with " + registrationId + " is not supported yet."
            );
        }
    }

    private User registerNewUser(OAuth2UserRequest userRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();
        
        AuthProvider provider = AuthProvider.valueOf(
            userRequest.getClientRegistration().getRegistrationId().toUpperCase() // GOOGLE, GITHUB, etc.
        );
        
        user.setProvider(provider);
        user.setProviderId(oAuth2UserInfo.getId());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());
        user.setEmailVerified(true);
        user.setPassword(""); // No password for OAuth2 users
        
        // Assign default role
        Role userRole = roleRepo.findByName("ROLE_CUSTOMER")
            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        user.setRole(userRole);
        
        return userRepo.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepo.save(existingUser);
    }
}
