package com.learning.security.services;

import com.learning.security.models.User;
import com.learning.security.repos.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepo userRepo;

    @Cacheable(value = "users", key = "#id")
    public Optional<User> findById(Integer id) {
        return userRepo.findById(id);
    }

    @Cacheable(value = "userByEmail", key = "#email")
    public Optional<User> findByEmail(String email) {
        return userRepo.findByEmail(email);
    }

    public Boolean existsByEmail(String email) {
        return userRepo.existsByEmail(email);
    }

    public Boolean existsByCnic(String cnic) {
        return userRepo.existsByCnic(cnic);
    }

    public List<User> findAll() {
        return userRepo.findAll();
    }

    @Caching(evict = {
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "userByEmail", allEntries = true)
    })
    public User save(User user) {
        return userRepo.save(user);
    }

    @Caching(evict = {
            @CacheEvict(value = "users", allEntries = true),
            @CacheEvict(value = "userByEmail", allEntries = true)
    })
    public void deleteById(Integer id) {
        userRepo.deleteById(id);
    }

    public long count() {
        return userRepo.count();
    }

    public long countByRoleId(Integer roleId) {
        return userRepo.countByRoleId(roleId);
    }

    public List<User> findByRoleName(String roleName) {
        return userRepo.findByRoleName(roleName);
    }

    public boolean existsById(Integer id) {
        return userRepo.existsById(id);
    }
}
