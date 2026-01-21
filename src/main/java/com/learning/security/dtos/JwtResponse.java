package com.learning.security.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {

    private String token;
    private final String type = "Bearer";
    private Integer id;
    private String email;
    private String role;

}
