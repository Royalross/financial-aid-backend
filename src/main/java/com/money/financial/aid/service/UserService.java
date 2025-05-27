package com.money.financial.aid.service;

import com.money.financial.aid.dtos.AuthResponse;
import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    @Value("${jwt.expiration-millis}")
    private long jwtExpirationMs;

    /**
     * Registers a new user:
     * - encrypts password
     * - saves to repository
     */
    public void registerUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    /**
     * Authenticates credentials, issues a JWT, and returns it.
     */
    public AuthResponse authenticateUser(LoginRequest loginRequest) {
        // 1) Authenticate against UserDetailsService/DaoAuthenticationProvider
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.email(),
                        loginRequest.password()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 2) Build JWT claims
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusMillis(jwtExpirationMs))
                .subject(authentication.getName())
                .claim("roles", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .build();

        // 3) Provide a JWS header specifying HS256 so the encoder picks our HMAC key
        JwsHeader jwsHeader = JwsHeader.with(() -> "HS256").build();

        // 4) Encode header + claims into a compact JWT
        String token = jwtEncoder
                .encode(JwtEncoderParameters.from(jwsHeader, claims))
                .getTokenValue();

        // 5) Return the token`
        return new AuthResponse(token, "Bearer");
    }

    /**
     * Retrieves a user by username or throws if not found.
     */
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found with username: " + username
                ));
    }
}
