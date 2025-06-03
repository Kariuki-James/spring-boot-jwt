package com.jmkariuki.springbootjwt.service;

import com.jmkariuki.springbootjwt.dto.AuthRegistrationRequest;
import com.jmkariuki.springbootjwt.exception.UsernameAlreadyExistsException;
import com.jmkariuki.springbootjwt.model.User;
import com.jmkariuki.springbootjwt.repository.UserRepository;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;

    @Autowired
    public UserService(
        UserRepository userRepository, PasswordEncoder passwordEncoder, JwtEncoder jwtEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
    }

    public String registerUser(AuthRegistrationRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException("Username already exists");
        }

        User user = new User();
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setEnabled(true);
        user.addAuthority("ROLE_USER");

        userRepository.save(user);
        return createToken();
    }

    public String createToken() {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
            .subject("user123")
            .issuedAt(now)
            .issuer("jmkariuki.app")
            .expiresAt(now.plusSeconds(3600))
            .claim("roles", "ROLE_USER")
            .build();

        JwsHeader header = JwsHeader.with(() -> "HS256").build();

        Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(header, claims));
        return jwt.getTokenValue();
    }
}
