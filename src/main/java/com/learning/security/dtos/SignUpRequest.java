package com.learning.security.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {
    
    @NotBlank
    @NotNull
    @Email
    private String email;
    
    @NotBlank
    @Size(min = 6, max = 30)
    @NotNull
    private String password;
    
    private String role;  // if null will be passed, by default it will be CUSTOMER

}

// Dummy JSON for testing:
// {
//   "email": "yousuf@gmail.com",
//   "password": "yousuf123",
//   "role": "admin"
// }
