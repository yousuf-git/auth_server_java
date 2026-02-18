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
    private String firstName;

    @NotBlank
    @NotNull
    private String lastName;

    @NotBlank
    @NotNull
    @Email
    private String email;
    
    @NotBlank
    @Size(min = 6, max = 30)
    @NotNull
    private String password;
    
    private String phone;

    private String role;  // looked up by name from DB; if null, no default assigned

}

/*
Example:
{
    "firstName": "admin",
    "lastName": "test",
    "email": "admin@test.com",
    "password": "admin123",
    "phone": "+1234567890"
}
 */