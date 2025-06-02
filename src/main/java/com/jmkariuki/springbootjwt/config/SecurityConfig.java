package com.jmkariuki.springbootjwt.config;

import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(
            auth -> {
              auth.anyRequest().permitAll();
            })
        .httpBasic(Customizer.withDefaults())
        .formLogin(Customizer.withDefaults())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

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

  //    @Bean
  //    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
  //        Map<String, JwtDecoder> jwtDecoders = new HashMap<>();
  //
  //        // Google JWTs
  //        String googleIssuer = "https://accounts.google.com";
  //        NimbusJwtDecoder googleDecoder = JwtDecoders.fromIssuerLocation(googleIssuer);
  //        jwtDecoders.put(googleIssuer, googleDecoder);
  //
  //        // Custom JWTs (example: your own issuer)
  //        String customIssuer = "https://your-app.com";
  //        NimbusJwtDecoder customDecoder =
  // NimbusJwtDecoder.withPublicKey(loadPublicKey()).build();
  //        jwtDecoders.put(customIssuer, customDecoder);
  //
  //        return new JwtIssuerAuthenticationManagerResolver(issuer -> {
  //            JwtDecoder decoder = jwtDecoders.get(issuer);
  //            if (decoder == null) {
  //                throw new BadJwtException("Unknown issuer: " + issuer);
  //            }
  //            return new JwtAuthenticationProvider(decoder)::authenticate;
  //        });
  //    }
  //
  //    private RSAPublicKey loadPublicKey() {
  //        return null;
  //    }
}
