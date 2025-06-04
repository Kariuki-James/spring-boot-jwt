package com.jmkariuki.springbootjwt.controller;

import com.jmkariuki.springbootjwt.dto.AuthRegistrationRequest;
import com.jmkariuki.springbootjwt.dto.HttpInfoResponse;
import com.jmkariuki.springbootjwt.exception.UsernameAlreadyExistsException;
import com.jmkariuki.springbootjwt.security.UserDetailsImpl;
import com.jmkariuki.springbootjwt.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, UserService userService) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
    }

    @PostMapping("/register-user")
    public ResponseEntity<HttpInfoResponse> registerUser(
        @Valid @RequestBody AuthRegistrationRequest request) {

        String token;
        try {
            token = userService.registerUser(request);
            return ResponseEntity.ok(
                new HttpInfoResponse(HttpStatus.OK.name(), token));
        } catch (UsernameAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body(
                new HttpInfoResponse(HttpStatus.CONFLICT.name(), e.getMessage())
            );
        }
    }

    @PostMapping("/login")
    public ResponseEntity<HttpInfoResponse> login(
        @Valid @RequestBody AuthRegistrationRequest request) {

        try {
            Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    request.username(),
                    request.password()
                )
            );

            UserDetailsImpl principal = (UserDetailsImpl) auth.getPrincipal();
            String token = userService.createToken(principal.getUser());

            return ResponseEntity.ok(
                new HttpInfoResponse(HttpStatus.OK.name(), token));

        } catch (AuthenticationException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new HttpInfoResponse(HttpStatus.UNAUTHORIZED.name(), "Invalid credentials"));
        }

    }
}
