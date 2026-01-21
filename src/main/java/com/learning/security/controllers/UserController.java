package com.learning.security.controllers;

import com.learning.security.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for user profile operations
 */
@RestController
@RequestMapping("/api/user")
@CrossOrigin(origins = "*", maxAge = 3600)
public class UserController {

    @Autowired
    private UserRepo userRepo;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        String email = authentication.getName();
        
        return userRepo.findByEmail(email)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}
