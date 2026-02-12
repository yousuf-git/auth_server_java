package com.learning.security.dtos.admin;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UpdateUserRequest {

    @Email
    private String email;

    @Size(min = 6, max = 30)
    private String password;

    @Size(max = 20)
    private String phone;

    private Integer roleId;

    private Boolean isLocked;
}
