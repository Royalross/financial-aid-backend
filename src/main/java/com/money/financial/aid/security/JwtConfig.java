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

@Configuration
public class JwtConfig {

    /**
     * Base64-encoded 256-bit HMAC secret (must decode to exactly 32 bytes)
     */
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    public JwtEncoder jwtEncoder() {
        // 1) Decode your Base64 secret into a raw HMAC-SHA256 key
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");

        // 2) Wrap it in a Nimbus OctetSequenceKey, explicitly HS256
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(hmacKey)
                .algorithm(JWSAlgorithm.HS256)
                .build();

        // 3) Put that single JWK into an ImmutableJWKSet source
        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(jwk));

        // 4) Give NimbusJwtEncoder that source — now it always finds your key
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecret);
        SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(hmacKey).build();
    }
}
