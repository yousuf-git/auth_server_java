package com.learning.security.models;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Timestamp;

/**
 * <h2>Permission Entity</h2>
 * <p>
 * Represents a permission that can be assigned to roles.
 * Permissions define what actions users with specific roles can perform.
 * </p>
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "permission")
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotBlank
    @NotNull
    @Column(length = 50, unique = true)
    private String name;

    @Column(length = 255)
    private String description;

    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdAt;

    @NotNull
    @Column(columnDefinition = "boolean default true")
    @Builder.Default
    private Boolean isActive = true;
}
