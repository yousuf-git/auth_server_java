package com.learning.security.controllers;

import com.learning.security.dtos.ResponseMessage;
import com.learning.security.dtos.UserDTO;
import com.learning.security.dtos.admin.ResetPasswordRequest;
import com.learning.security.services.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/manager")
@Validated
public class ManagerController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/customers")
    @PreAuthorize("hasAnyAuthority('ROLE_PLANT_MANAGER', 'ROLE_ADMIN')")
    public ResponseEntity<List<UserDTO>> getAllCustomers() {
        List<UserDTO> customers = userService.findByRoleName("ROLE_CUSTOMER").stream()
                .map(UserDTO::fromEntity)
                .collect(Collectors.toList());
        return ResponseEntity.ok(customers);
    }

    @PutMapping("/reset-password/{userId}")
    @PreAuthorize("hasAnyAuthority('ROLE_PLANT_MANAGER', 'ROLE_ADMIN')")
    public ResponseEntity<?> resetPassword(@PathVariable @Positive Integer userId,
                                           @Valid @RequestBody ResetPasswordRequest request) {
        return userService.findById(userId)
                .map(user -> {
                    user.setPassword(passwordEncoder.encode(request.getNewPassword()));
                    userService.save(user);
                    return ResponseEntity.ok(new ResponseMessage("Password reset successfully"));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
