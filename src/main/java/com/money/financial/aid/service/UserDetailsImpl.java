package com.money.financial.aid.service;

import com.money.financial.aid.model.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Custom UserDetails implementation to adapt our User entity for Spring Security.
 */
@Getter
@AllArgsConstructor
public class UserDetailsImpl implements UserDetails, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private final Long id;
    private final String username;
    private final String email;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;
    private final boolean enabled;

    /**
     * Factory method to build UserDetailsImpl from User entity.
     */
    public static UserDetailsImpl build(User user) {
        // Convert user roles to GrantedAuthority objects required by Spring Security.
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return new UserDetailsImpl(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities,
                user.isEnabled()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    // The following account checks can be extended for advanced features (lockout, expiration, etc.)
    @Override
    public boolean isAccountNonExpired() {
        return true; // Modify if supporting account expiration
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Modify if supporting account lockout
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Modify if supporting password expiration
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
