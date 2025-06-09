package com.money.financial.aid.repository;

import com.money.financial.aid.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repository interface for User entity.
 * Provides basic CRUD operations and custom queries.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find a user by their username.
     */
    Optional<User> findByUsername(String username);

    /**
     * Find a user by their email.
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if a username already exists.
     */
    Boolean existsByUsername(String username);

    /**
     * Check if an email is already registered.
     */
    Boolean existsByEmail(String email);

}
