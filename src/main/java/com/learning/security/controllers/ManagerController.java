package com.learning.security.controllers;

import com.learning.security.dtos.ResponseMessage;
import com.learning.security.models.User;
import com.learning.security.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Controller for Plant Manager operations
 */
@RestController
@RequestMapping("/api/manager")
@CrossOrigin(origins = "*", maxAge = 3600)
public class ManagerController {

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/customers")
    @PreAuthorize("hasAnyAuthority('ROLE_PLANT_MANAGER', 'ROLE_ADMIN')")
    public ResponseEntity<List<User>> getAllCustomers() {
        List<User> customers = userRepo.findAll();
        return ResponseEntity.ok(customers);
    }

    @PutMapping("/reset-password/{userId}")
    @PreAuthorize("hasAnyAuthority('ROLE_PLANT_MANAGER', 'ROLE_ADMIN')")
    public ResponseEntity<?> resetPassword(@PathVariable Integer userId, @RequestBody Map<String, String> request) {
        String newPassword = request.get("newPassword");
        
        if (newPassword == null || newPassword.length() < 6) {
            return ResponseEntity.badRequest().body(new ResponseMessage("Password must be at least 6 characters"));
        }

        return userRepo.findById(userId)
                .map(user -> {
                    user.setPassword(passwordEncoder.encode(newPassword));
                    userRepo.save(user);
                    return ResponseEntity.ok(new ResponseMessage("Password reset successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
