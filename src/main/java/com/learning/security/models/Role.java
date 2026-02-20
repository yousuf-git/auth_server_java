// User will have multiple roles, so we need to create a Role entity to store the roles in the database

package com.learning.security.models;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.sql.Timestamp;
import java.util.HashSet;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@RequiredArgsConstructor
@Entity
@Table(name = "role")
@Builder
public class Role implements java.io.Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id", updatable = false, nullable = false)
    private Integer id;

    // Role name can be any string value
    @NotBlank
    @NotNull
    @Column(length = 100, unique = true)
    @NonNull        // for lombok - I needed parameterized constructor Role(String name)
    private String name;

    @Column(length = 255)
    private String description;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Timestamp createdAt;

    @NotNull
    @Column(name = "is_active", columnDefinition = "boolean default false")
    @Builder.Default
    private Boolean isActive = false;

    @JsonIgnore
    @ManyToMany(fetch = FetchType.LAZY, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "role_permission",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();

    public static Role of(String name) {
        return new Role(name);
    }

}

/*
Role {
    id: 1,
    name: "ROLE_SUPER_ADMIN",
    description: "Admin role with all permissions",
    createdAt: 2024-06-01T12:00:00Z,
    isActive: true,
    permissions: [
        Permission {
            id: 1,
            name: "READ_PRIVILEGES",
            description: "Permission to read data",
            createdAt: 2024-06-01T12:00:00Z,
            isActive: true
        },
        Permission {
            id: 2,
            name: "WRITE_PRIVILEGES",
            description: "Permission to write data",
            createdAt: 2024-06-01T12:00:00Z,
            isActive: true
        }
    ]
 */
