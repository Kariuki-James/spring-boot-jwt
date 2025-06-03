package com.jmkariuki.springbootjwt.controller;

import com.jmkariuki.springbootjwt.dto.HttpInfoResponse;
import java.util.HashMap;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public HttpInfoResponse hello() throws IllegalAccessException {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        Authentication authentication = securityContext.getAuthentication();
        Jwt principal = (Jwt) authentication.getPrincipal();

        HashMap<String, Object> resultMap = new HashMap<>();
        resultMap.put("claims", principal.getClaims());
        resultMap.put("token", principal.getTokenValue());

        return new HttpInfoResponse(HttpStatus.OK.name(), resultMap);
    }

}
