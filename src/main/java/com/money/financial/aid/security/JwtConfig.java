package com.money.financial.aid.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Configuration for JWT encoder/decoder using HMAC (HS256).
 * Secret is provided as a base64 string in configuration.
 */
@Configuration
public class JwtConfig {

    /**
     * Base64-encoded 256-bit HMAC secret (must decode to exactly 32 bytes).
     */
    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * JWT encoder bean (for creating tokens).
     */
    @Bean
    public JwtEncoder jwtEncoder() {
        // Decode the base64 secret into bytes.
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        // Build a JWK key for Nimbus.
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(hmacKey)
                .algorithm(JWSAlgorithm.HS256)
                .build();

        // Create the JWK source for the encoder.
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwkSource);
    }

    /**
     * JWT decoder bean (for validating tokens).
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(hmacKey).build();
    }
}
