package com.money.financial.aid.service;

import com.money.financial.aid.dtos.LoginRequest;
import com.money.financial.aid.dtos.AuthResponse;
import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class UserServiceTest {

    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtEncoder jwtEncoder;
    private UserService userService;

    @BeforeEach
    void setup() {
        userRepository = Mockito.mock(UserRepository.class);
        passwordEncoder = new BCryptPasswordEncoder();
        authenticationManager = Mockito.mock(AuthenticationManager.class);
        jwtEncoder = Mockito.mock(JwtEncoder.class);

        userService = new UserService(userRepository, passwordEncoder, authenticationManager, jwtEncoder);
        ReflectionTestUtils.setField(userService, "jwtExpirationMs", 3600000L);
        ReflectionTestUtils.setField(userService, "jwtIssuer", "test-issuer");
    }

    @Test
    void registerUserHashesPassword() {
        User user = new User();
        user.setUsername("bob");
        user.setEmail("bob@example.com");
        user.setPassword("plainpass");
        user.setRoles(Set.of("ROLE_USER"));

        userService.registerUser(user);

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        User saved = captor.getValue();
        assertTrue(passwordEncoder.matches("plainpass", saved.getPassword()));
    }

    @Test
    void authenticateUserReturnsToken() {
        LoginRequest req = new LoginRequest("bob", "secret");
        Authentication auth = Mockito.mock(Authentication.class);
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(auth);
        when(auth.getName()).thenReturn("bob");
        when(auth.getAuthorities()).thenReturn(Set.of());

        Jwt jwt = Jwt.withTokenValue("token").header("alg", "HS256").claim("sub", "bob").build();
        when(jwtEncoder.encode(any(JwtEncoderParameters.class))).thenReturn(jwt);

        AuthResponse resp = userService.authenticateUser(req);
        assertEquals("token", resp.token());
        assertEquals("Bearer", resp.tokenType());
    }
}
