package com.learning.security.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
@CrossOrigin(origins = "*", maxAge = 3600)      // 3600 sec = 1 hr
public class TestController {

    @GetMapping("/all")
    public String publicContent() {
        return "This endpoint is available for all";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN') or hasRole('MODERATOR')")
    public String getUserContent() {
        return "User's Content is here :)";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('ADMIN') or hasRole('MODERATOR')")
    public String getModContent() {
        return "Mod's Content is here :)";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String getAdminContent() {
        return "Admin's Content is here :)";
    }

}
