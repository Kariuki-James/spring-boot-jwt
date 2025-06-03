package com.jmkariuki.springbootjwt.controller;

import com.jmkariuki.springbootjwt.dto.HttpInfoResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

  @GetMapping("/hello")
  public HttpInfoResponse hello() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();

    return new HttpInfoResponse(HttpStatus.OK.name(), authentication.getPrincipal());
  }

}
