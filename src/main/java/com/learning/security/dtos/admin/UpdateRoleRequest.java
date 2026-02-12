package com.learning.security.dtos.admin;

import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.List;

@Data
public class UpdateRoleRequest {

    @Size(max = 100)
    private String name;

    @Size(max = 255)
    private String description;

    private List<Integer> permissionIds;
}
