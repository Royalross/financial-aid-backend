package com.money.financial.aid.dtos;

/**
 * Returned after successful authentication, contains the JWT and its type.
 */
public record AuthResponse(String token, String tokenType) {
}
