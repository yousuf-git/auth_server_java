package com.learning.security.repos;

import org.springframework.stereotype.Repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import com.learning.security.models.User;

@Repository
public interface UserRepo extends JpaRepository<User, Integer> {

    Optional<User> findByEmail(String email);
    Boolean existsByEmail(String email);

}
