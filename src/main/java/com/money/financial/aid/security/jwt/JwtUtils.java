package com.money.financial.aid.security.jwt;

import com.money.financial.aid.service.UserDetailsImpl;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * JWT Token Management
 * <p>
 * Handles JWT operations including token generation, extraction,
 * validation, and parsing. This is a core component of the
 * stateless authentication system.
 */
@Component
public class JwtUtils {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpiration;

    /**
     * Extract JWT Token from HTTP Request
     * <p>
     * Retrieves the JWT token from the Authorization header,
     * removing the "Bearer " prefix if present.
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            // Return only the token part, not the "Bearer " prefix
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Generate JWT Token
     * <p>
     * Creates a signed JWT token after successful authentication.
     * The token contains the username as subject, user roles as claims,
     * issuance time, and expiration time. It's signed with a secret key
     * to ensure its integrity.
     */
    public String generateToken(UserDetailsImpl userDetails) {
        String username = userDetails.getUsername();
        // Convert the user's authorities/roles to a comma-separated string
        String roles = userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining(","));

        // Build and return the JWT token
        return Jwts.builder()
                .subject(username)                // Set the subject (username)
                .claim("roles", roles)            // Add roles as a claim
                .issuedAt(new Date())             // Set issued time to now
                .expiration(new Date((new Date().getTime() + jwtExpiration))) // Set expiration
                .signWith(key())                  // Sign with our secret key
                .compact();                       // Generate the compact token string
    }

    /**
     * Extract Username from JWT Token
     * <p>
     * Parses the JWT token, verifies its signature, and
     * extracts the username (subject) from it.
     */
    public String getUserNameFromToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * Creates the cryptographic key used to sign and verify JWT tokens
     * using the configured secret
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    /**
     * Validate JWT Token
     * <p>
     * Checks if a token is valid by attempting to parse it with the secret key.
     * Returns true if parsing succeeds, throws an exception if the token is invalid.
     */
    public boolean validateToken(String authtoken) {
        try {
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build().parseSignedClaims(authtoken);
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
