package com.jmkariuki.springbootjwt.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${custom.security.jwt.issuer.google}")
    private String googleIssuer;


    private final OctetSequenceKey jwk;

    public SecurityConfig() throws JOSEException {
        this.jwk = new OctetSequenceKeyGenerator(256).generate();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(
                auth -> {
                    auth
                        .requestMatchers("/auth/register-user").permitAll()
                        .requestMatchers("/auth/login").permitAll()
                        .anyRequest().authenticated();
                })
            .oauth2ResourceServer(oauth2 ->
                oauth2.authenticationManagerResolver(authenticationManagerResolver()));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder nimbusJwtEncoder() throws JOSEException {
        JWKSet jwkSet = new JWKSet(this.jwk);
        JWKSource<SecurityContext> jwkSource = ((jwkSelector, securityContext) ->
            jwkSelector.select(jwkSet));

        return new NimbusJwtEncoder(jwkSource);
    }

    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        Map<String, JwtDecoder> jwtDecoders = new HashMap<>();

        // Google JWTs
        NimbusJwtDecoder googleDecoder = JwtDecoders.fromIssuerLocation(googleIssuer);
        jwtDecoders.put(googleIssuer, googleDecoder);

        // Custom JWTs
        NimbusJwtDecoder customDecoder = NimbusJwtDecoder
            .withSecretKey(this.jwk.toSecretKey())
            .build();
        jwtDecoders.put(applicationName, customDecoder);

        return new JwtIssuerAuthenticationManagerResolver(issuer -> {
            JwtDecoder decoder = jwtDecoders.get(issuer);
            if (decoder == null) {
                throw new BadJwtException("Unknown issuer: " + issuer);
            }
            return new JwtAuthenticationProvider(decoder)::authenticate;
        });
    }

    // Custom CORS configuration source
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
