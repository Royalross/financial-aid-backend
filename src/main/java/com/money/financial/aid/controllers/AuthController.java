package com.money.financial.aid.controllers;

import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.dtos.RegisterRequest;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import com.money.financial.aid.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashSet;

/**
 * Controller for authentication endpoints.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;

    /**
     * Handles user registration.
     * - Only allows default role assignment.
     * - Avoids leaking if username/email is already registered.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest req) {
        // no duplicates
        if (userRepository.existsByUsername(req.username()) || userRepository.existsByEmail(req.email())) {
            return ResponseEntity.badRequest().body("Error: Registration failed. Username or email already in use.");
        }

        // Always assign default role
        User user = new User();
        user.setUsername(req.username());
        user.setEmail(req.email());
        user.setPassword(req.password()); // Will be securely hashed in service layer.
        user.setRoles(new HashSet<>(Collections.singletonList("ROLE_USER")));

        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    /**
     * Authenticates a user and returns a JWT on success.
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.authenticateUser(loginRequest));
    }

}
