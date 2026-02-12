package com.learning.security.services;

import com.learning.security.models.Role;
import com.learning.security.repos.RoleRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class RoleService {

    @Autowired
    private RoleRepo roleRepo;

    @Cacheable(value = "roles", key = "#id") // Spring uses SpEL (Spring Expression Language) here to dynamically generate keys based on method arguments.
    public Optional<Role> findById(Integer id) {
        return roleRepo.findById(id);
    }

    @Cacheable(value = "roles", key = "'name:' + #name")
    public Optional<Role> findByName(String name) {
        return roleRepo.findByName(name);
    }

    public Boolean existsByName(String name) {
        return roleRepo.existsByName(name);
    }

    public List<Role> findAll() {
        return roleRepo.findAll();
    }

    @CacheEvict(value = "roles", allEntries = true)
    public Role save(Role role) {
        return roleRepo.save(role);
    }

    @CacheEvict(value = "roles", allEntries = true)
    public void deleteById(Integer id) {
        roleRepo.deleteById(id);
    }

    public boolean existsById(Integer id) {
        return roleRepo.existsById(id);
    }
}
