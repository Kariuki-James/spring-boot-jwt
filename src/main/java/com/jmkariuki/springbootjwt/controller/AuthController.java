package com.jmkariuki.springbootjwt.controller;

import com.jmkariuki.springbootjwt.dto.AuthRegistrationRequest;
import com.jmkariuki.springbootjwt.dto.HttpInfoResponse;
import com.jmkariuki.springbootjwt.exception.UsernameAlreadyExistsException;
import com.jmkariuki.springbootjwt.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final UserService userService;

  @Autowired
  public AuthController(UserService userService) {
    this.userService = userService;
  }

  @PostMapping("/register-user")
  public ResponseEntity<HttpInfoResponse> registerUser(
      @Valid @RequestBody AuthRegistrationRequest request) {
    try {
      userService.registerUser(request);
    } catch (UsernameAlreadyExistsException e) {
      return ResponseEntity.status(HttpStatus.CONFLICT).body(
          new HttpInfoResponse(HttpStatus.CONFLICT.name(), e.getMessage())
      );
    }

    return ResponseEntity.ok(
        new HttpInfoResponse(HttpStatus.OK.name(), "User registered successfully"));
  }
}
