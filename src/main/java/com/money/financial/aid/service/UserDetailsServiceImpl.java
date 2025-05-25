package com.money.financial.aid.service;

import com.money.financial.aid.model.User;
import com.money.financial.aid.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;


@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // In this application, the username parameter is actually the email
        // Find the user in the database by email
        User userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with email: " + username));

        // Convert the User entity to Spring Security's UserDetails implementation
        // This adapts our user model to what Spring Security expects
        return UserDetailsImpl.build(userEntity);
    }
}
