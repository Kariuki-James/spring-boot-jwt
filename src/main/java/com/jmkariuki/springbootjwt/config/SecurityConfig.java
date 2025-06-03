package com.jmkariuki.springbootjwt.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
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
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final OctetSequenceKey JWK;

    public SecurityConfig() throws JOSEException {
        this.JWK = new OctetSequenceKeyGenerator(256).generate();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(
                auth -> {
                    auth
                        .requestMatchers("/auth/register-user").permitAll()
                        .anyRequest().authenticated();
                })
            .httpBasic(Customizer.withDefaults())
            .formLogin(Customizer.withDefaults())
            .oauth2ResourceServer(oauth2 ->
                oauth2.authenticationManagerResolver(authenticationManagerResolver()));

        return http.build();
    }

    @Bean
    UserDetailsManager users(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public JwtEncoder nimbusJwtEncoder() throws JOSEException {
        JWKSet jwkSet = new JWKSet(this.JWK);
        JWKSource<SecurityContext> jwkSource = ((jwkSelector, securityContext) ->
            jwkSelector.select(jwkSet));

        return new NimbusJwtEncoder(jwkSource);
    }

    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        Map<String, JwtDecoder> jwtDecoders = new HashMap<>();

        // Google JWTs
        String googleIssuer = "https://accounts.google.com";
        NimbusJwtDecoder googleDecoder = JwtDecoders.fromIssuerLocation(googleIssuer);
        jwtDecoders.put(googleIssuer, googleDecoder);

        // Custom JWTs
        String customIssuer = "jmkariuki.app";
        NimbusJwtDecoder customDecoder = NimbusJwtDecoder
            .withSecretKey(this.JWK.toSecretKey())
            .build();
        jwtDecoders.put(customIssuer, customDecoder);

        return new JwtIssuerAuthenticationManagerResolver(issuer -> {
            JwtDecoder decoder = jwtDecoders.get(issuer);
            if (decoder == null) {
                throw new BadJwtException("Unknown issuer: " + issuer);
            }
            return new JwtAuthenticationProvider(decoder)::authenticate;
        });
    }
}
