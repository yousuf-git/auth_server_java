package com.learning.security.dtos.admin;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateUserRequest {

    private String firstName;

    private String lastName;

    @Email
    private String email;

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
