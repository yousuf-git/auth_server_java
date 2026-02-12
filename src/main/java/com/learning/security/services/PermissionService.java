package com.learning.security.services;

import com.learning.security.models.Permission;
import com.learning.security.repos.PermissionRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PermissionService {

    @Autowired
    private PermissionRepo permissionRepo;

    @Cacheable(value = "permissions", key = "#id")
    public Optional<Permission> findById(Integer id) {
        return permissionRepo.findById(id);
    }

    public Boolean existsByName(String name) {
        return permissionRepo.existsByName(name);
    }

    public List<Permission> findAll() {
        return permissionRepo.findAll();
    }

    @CacheEvict(value = "permissions", allEntries = true)
    public Permission save(Permission permission) {
        return permissionRepo.save(permission);
    }

    @CacheEvict(value = "permissions", allEntries = true)
    public void deleteById(Integer id) {
        permissionRepo.deleteById(id);
    }

    public boolean existsById(Integer id) {
        return permissionRepo.existsById(id);
    }
}
