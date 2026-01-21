package com.learning.security.models;

import com.learning.security.enums.AuthProvider;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Enumerated;
import jakarta.persistence.EnumType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.FetchType;

import java.sql.Timestamp;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


/**
 * <h2>User Entity</h2>
 * <p>
 * Represents a user in the system with complete audit trail and security features.
 * </p>
 * <ul>
 *   <li>Supports both local authentication and OAuth2 providers</li>
 *   <li>Includes account locking mechanism for security</li>
 *   <li>Maintains full audit trail of user actions</li>
 * </ul>
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "email"),
                @UniqueConstraint(columnNames = "phone")
        })
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @NotBlank
    @Column(length = 50)
    @NotNull
    private String email;

    @Column(length = 120)
    private String password;

    @Column(length = 20, unique = true)
    private String phone;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private AuthProvider provider;

    @Column(length = 100)
    private String providerId;

    @Column(length = 500)
    private String imageUrl;

    @Column(columnDefinition = "boolean default false")
    private Boolean emailVerified = false;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private Role role;

    // Audit and tracking fields
    @CreationTimestamp
    @Column(updatable = false)
    private Timestamp createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @UpdateTimestamp
    private Timestamp modifiedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "modified_by")
    private User modifiedBy;

    // Account locking fields
    @NotNull
    @Column(columnDefinition = "boolean default false")
    private Boolean isLocked = false;

    private Timestamp lockedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "locked_by")
    private User lockedBy;

    private Timestamp unlockedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "unlocked_by")
    private User unlockedBy;

}
