package com.money.financial.aid.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload for user registration.
 *
 */
public record RegisterRequest(
        @NotBlank @Email(message = "Email should be valid") @Size(max = 100) String email,
        @NotBlank @Size(min = 8, max = 120) String password,
        @NotBlank @Size(min = 3, max = 50) String username
) {
}
