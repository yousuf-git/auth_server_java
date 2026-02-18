package com.learning.security.dtos.admin;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class CreateUserRequest {

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = 6, max = 30)
    private String password;

    @Size(max = 25)
    private String cnic;

    @Size(max = 100)
    private String country;

    @Size(max = 100)
    private String city;

    @Size(max = 100)
    private String province;

    @Size(max = 100)
    private String area;

    @Size(max = 255)
    private String address;

    @Size(max = 20)
    private String phone;

    private Integer roleId;

    private Boolean isLocked;
}
