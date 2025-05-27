package com.money.financial.aid.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // 1) CORS for React on localhost:3000
                .cors(Customizer.withDefaults())
                // 2) Stateless, no CSRF
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 3) Public auth endpoints, secure everything else
                .authorizeHttpRequests(auth ->
                        auth
                                .requestMatchers("/auth/**").permitAll()
                                .anyRequest().authenticated()
                )
                // 4) JWT validation
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
        ;

        // 5) wire in DAO provider for login
        http.authenticationProvider(daoAuthProvider());
        return http.build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /** expose the autoconfigured AuthenticationManager */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig
    ) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Global CORS configuration to allow your Front end to call this API.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of("http://localhost:3000"));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cfg.setAllowCredentials(true);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
