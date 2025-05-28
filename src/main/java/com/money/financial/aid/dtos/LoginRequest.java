package com.money.financial.aid.dtos;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload for login requests.
 */
public record LoginRequest(
        @NotBlank(message = "Username or email is required") String login,
        @NotBlank @Size(min = 8, message = "Password must be at least 8 characters") String password
) {
}
