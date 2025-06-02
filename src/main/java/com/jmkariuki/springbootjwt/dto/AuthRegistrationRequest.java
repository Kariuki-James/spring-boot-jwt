package com.jmkariuki.springbootjwt.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthRegistrationRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, message = "Username must be longer than 2 characters")
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Username must be longer than 5 characters")
    String password) {

}
