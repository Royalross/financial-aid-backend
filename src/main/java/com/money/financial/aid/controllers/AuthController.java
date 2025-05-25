package com.money.financial.aid.controllers;

import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.dtos.RegisterRequest;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import com.money.financial.aid.service.UserService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashSet;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;

    /**
     * Handles user registration.
     * Steps:
     * 1. Validate the request data.
     * 2. Check if a username or email already exists.
     * 3. Create a new User object from the request.
     * 4. Set the default role if none is provided.
     * 5. Register the user via UserService.
     */

    //http://localhost:8080/auth/register
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        // Check if username is already taken
        if (userRepository.existsByUsername(request.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Username is already taken!");
        }

        // Check if email is already in use
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body("Error: Email is already in use!");
        }

        // Create a new user
        User user = new User();
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());

        // Set default role if none provided
        if (request.getRoles() == null || request.getRoles().isEmpty()) {
            user.setRoles(new HashSet<>(Collections.singletonList("ROLE_USER")));
        } else {
            user.setRoles(request.getRoles());
        }

        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    /**
     * Handles user login.
     * Steps:
     * 1. Validate the request data.
     * 2. Authenticate user credentials.
     * 3. Generate a JWT token upon successful authentication.
     * 4. Return the token in the response.
     */

    /*
    Post: http://localhost:8080/auth/login
    {
    "email": "",
    "password": ""
}
     */
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.authenticateUser(loginRequest));
    }
}
