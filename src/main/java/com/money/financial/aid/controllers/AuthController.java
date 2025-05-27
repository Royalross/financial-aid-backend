package com.money.financial.aid.controllers;

import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.dtos.RegisterRequest;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import com.money.financial.aid.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashSet;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest req) {
        if (userRepository.existsByUsername(req.username())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }
        if (userRepository.existsByEmail(req.email())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        User user = new User();
        user.setUsername(req.username());
        user.setEmail(req.email());
        user.setPassword(req.password());
        user.setRoles(
                (req.roles() == null || req.roles().isEmpty())
                        ? new HashSet<>(Collections.singletonList("ROLE_USER"))
                        : req.roles()
        );

        userService.registerUser(user);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(userService.authenticateUser(loginRequest));
    }
}
