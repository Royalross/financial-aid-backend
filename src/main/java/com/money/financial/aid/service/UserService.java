package com.money.financial.aid.service;

import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import com.money.financial.aid.security.jwt.JwtAuthenticationResponse;
import com.money.financial.aid.security.jwt.JwtUtils;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    /**
     * Registers a new user.
     * Steps:
     * 1. Encode the user's password.
     * 2. Save the user to the repository.
     */
    public void registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    /**
     * Authenticates a user and generates a JWT token.
     * Steps:
     * 1. Authenticate the user's credentials.
     * 2. Generate a JWT token upon successful authentication.
     * 3. Return the token in the response.
     */
    public JwtAuthenticationResponse authenticateUser(LoginRequest loginRequest) {
        // Authenticate the user
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getEmail(),
                        loginRequest.getPassword()
                )
        );

        // Set the authentication in the security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Get the user details
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Generate JWT token
        String jwt = jwtUtils.generateToken(userDetails);

        // Return the response with the token
        JwtAuthenticationResponse response = new JwtAuthenticationResponse();
        response.setToken(jwt);
        return response;
    }

    /**
     * Finds a user by username.
     * Steps:
     * 1. Retrieve the user from the repository.
     * 2. Throw an exception if the user is not found.
     */
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));
    }
}
