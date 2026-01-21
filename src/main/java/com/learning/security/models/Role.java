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
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
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
    @Column(updatable = false)
    private Timestamp createdAt;

    @NotNull
    @Column(columnDefinition = "boolean default true")
    @Builder.Default
    private Boolean isActive = true;

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
