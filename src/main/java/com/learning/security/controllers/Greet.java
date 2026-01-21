// This is a controller class that is used to greet the user and test the application.

package com.learning.security.controllers;

import org.springframework.web.bind.annotation.RestController;
// import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@RestController
@RequestMapping("/greet")
public class Greet {
    
    @GetMapping("")
    public String hi() {
        return "Greetings !";
    }
}
