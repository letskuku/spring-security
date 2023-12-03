package com.example.springsecurity.configures;

import com.example.springsecurity.jwt.Jwt;
import com.example.springsecurity.jwt.JwtProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class JwtConfigure {

    private JwtProperties jwtProperties;

    @Autowired
    public void setJwtConfigure(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    @Bean
    public Jwt jwt() {
        return new Jwt(
                jwtProperties.getIssuer(),
                jwtProperties.getClientSecret(),
                jwtProperties.getExpirySeconds()
        );
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
