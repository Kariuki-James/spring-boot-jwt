package com.jmkariuki.springbootjwt.controller;

import com.jmkariuki.springbootjwt.dto.AuthRegistrationRequest;
import com.jmkariuki.springbootjwt.dto.HelloResponse;
import com.jmkariuki.springbootjwt.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

  private final UserService userService;

  @Autowired
  public AuthController(UserService userService) {
    this.userService = userService;
  }

  @GetMapping("/hello")
  public HelloResponse hello() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();

    return new HelloResponse(authentication.getPrincipal(), authentication.getAuthorities());
  }

  @PostMapping("/register")
  public ResponseEntity<String> registerUser(@Valid @RequestBody AuthRegistrationRequest request) {
    userService.registerUser(request);
    return ResponseEntity.ok("User registered successfully");
  }
}
