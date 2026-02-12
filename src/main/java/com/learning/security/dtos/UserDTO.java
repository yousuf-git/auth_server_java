package com.learning.security.dtos;

import com.learning.security.models.User;
import lombok.Builder;
import lombok.Data;

import java.io.Serializable;
import java.sql.Timestamp;

@Data
@Builder
public class UserDTO implements Serializable {

    private Integer id;
    private String email;
    private String phone;
    private String provider;
    private Boolean emailVerified;
    private String roleName;
    private Boolean isLocked;
    private Timestamp createdAt;
    private Timestamp modifiedAt;
    private String imageUrl;

    public static UserDTO fromEntity(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .email(user.getEmail())
                .phone(user.getPhone())
                .provider(user.getProvider() != null ? user.getProvider().name() : null)
                .emailVerified(user.getEmailVerified())
                .roleName(user.getRole() != null ? user.getRole().getName() : null)
                .isLocked(user.getIsLocked())
                .createdAt(user.getCreatedAt())
                .modifiedAt(user.getModifiedAt())
                .imageUrl(user.getImageUrl())
                .build();
    }
}
