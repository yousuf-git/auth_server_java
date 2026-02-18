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
                @UniqueConstraint(columnNames = "cnic")
        })
public class User implements java.io.Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", updatable = false, nullable = false)
    private Integer id;

    @NotBlank
    @Column(name = "first_name", length = 100, nullable = false)
    @NotNull
    private String firstName;

    @NotBlank
    @Column(name = "last_name", length = 100, nullable = false)
    @NotNull
    private String lastName;

    @Column(name = "cnic", length = 25, unique = true)
    private String cnic;

    @Column(name = "country", length = 100)
    private String country;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "province", length = 100)
    private String province;

    @Column(name = "area", length = 100)
    private String area;

    @Column(name = "address", length = 255)
    private String address;

    @NotBlank
    @Column(name = "email", length = 255, nullable = false)
    @NotNull
    private String email;

    @Column(name = "password_hash", length = 120)
    private String password;

    @Column(name = "phone", length = 20)
    private String phone;

    @Enumerated(EnumType.STRING)
        @Column(name = "provider", length = 20)
    private AuthProvider provider;

        @Column(name = "provider_id", length = 100)
    private String providerId;

        @Column(name = "image_url", length = 500)
    private String imageUrl;

        @Column(name = "is_email_verified", columnDefinition = "boolean default false")
    private Boolean emailVerified = false;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private Role role;

    // Audit and tracking fields
    @CreationTimestamp
        @Column(name = "created_at", updatable = false)
    private Timestamp createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "created_by")
    private User createdBy;

    @UpdateTimestamp
        @Column(name = "modified_at")
        private Timestamp modifiedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "modified_by")
    private User modifiedBy;

    // Account locking fields
    @NotNull
        @Column(name = "is_locked", columnDefinition = "boolean default false")
    private Boolean isLocked = false;

        @Column(name = "locked_at")
    private Timestamp lockedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "locked_by")
    private User lockedBy;

        @Column(name = "unlocked_at")
    private Timestamp unlockedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "unlocked_by")
    private User unlockedBy;

}
