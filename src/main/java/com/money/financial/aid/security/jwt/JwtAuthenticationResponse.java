package com.money.financial.aid.security.jwt;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Authentication Response
 * <p>
 * Data Transfer Object (DTO) that wraps the JWT token for the client
 * after successful authentication. The client will store this token
 * and include it in later requests to access protected resources.
 */
@Data
@NoArgsConstructor
public class JwtAuthenticationResponse {
    /**
     * JWT Token
     * <p>
     * Contains the signed JWT token with user identity, roles, and expiration.
     * The client includes this in the Authorization header as "Bearer {token}"
     * for later authenticated requests.
     */
    private String token;

    private String tokenType = "Bearer";

}
