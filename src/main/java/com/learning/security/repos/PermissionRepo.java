package com.learning.security.repos;

import com.learning.security.models.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * <h2>PermissionRepository</h2>
 * <p>
 * Repository interface for Permission entity.
 * Provides CRUD operations and custom query methods for Permission management.
 * </p>
 */
@Repository
public interface PermissionRepo extends JpaRepository<Permission, Integer> {
    
    /**
     * Find a permission by its name
     * @param name the permission name
     * @return Optional containing the permission if found
     */
    Optional<Permission> findByName(String name);
    
    /**
     * Check if a permission exists by name
     * @param name the permission name
     * @return true if permission exists, false otherwise
     */
    boolean existsByName(String name);
}
