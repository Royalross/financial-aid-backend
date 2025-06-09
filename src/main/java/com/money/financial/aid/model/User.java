package com.money.financial.aid.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.HashSet;
import java.util.Set;

/**
 * JPA entity for application users.
 */
@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email")
        })
@Data
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(min = 3, max = 50)
    private String username;

    @NotBlank
    @Size(max = 100)
    @Email
    private String email;

    // Will be hashed! Don't serialize to clients.
    @JsonIgnore // Prevents password exposure in any JSON serialization
    @NotBlank
    @Size(min = 8, max = 120)
    @Column(length = 120)
    private String password;

    // Stores roles for user. Set only by backend logic.
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> roles = new HashSet<>();

    // Optional profile picture
    private String profilePicture;

    // True if the account is enabled (not banned/locked).
    private boolean enabled = true;
}
