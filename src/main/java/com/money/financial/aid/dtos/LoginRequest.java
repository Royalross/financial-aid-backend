package com.money.financial.aid.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload for login.
 */
public record LoginRequest(
        @NotBlank @Email(message = "Email should be valid") String email,
        @NotBlank @Size(min = 8, message = "Password must be at least 8 characters") String password
) {
}
