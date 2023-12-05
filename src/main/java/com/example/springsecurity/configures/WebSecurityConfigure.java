package com.example.springsecurity.configures;

import com.example.springsecurity.jwt.*;
import com.example.springsecurity.oauth2.OAuth2AuthenticationSuccessHandler;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.*;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigure {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final JwtProperties jwtProperties;

    private final Jwt jwt;

    public WebSecurityConfigure(JwtProperties jwtProperties, Jwt jwt) {
        this.jwtProperties = jwtProperties;
        this.jwt = jwt;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers(new AntPathRequestMatcher("/h2-console/**"));
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, e) -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Object principal = authentication != null ? authentication.getPrincipal() : null;
            log.warn("{} is denied", principal, e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("text/plain;charset=UTF-8");
            response.getWriter().write("ACCESS DENIED");
            response.getWriter().flush();
            response.getWriter().close();
        };
    }

    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter(jwtProperties.getHeader(), jwt);
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers(new AntPathRequestMatcher("/api/user/me")).hasAnyRole("USER", "ADMIN")
                        .anyRequest().permitAll())
                .formLogin(FormLoginConfigurer::disable)
                .csrf(CsrfConfigurer::disable)
                .headers(HeadersConfigurer::disable)
                .httpBasic(HttpBasicConfigurer::disable)
                .rememberMe(RememberMeConfigurer::disable)
                .logout(LogoutConfigurer::disable)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2LoginConfigurer -> oauth2LoginConfigurer
                        .successHandler(oAuth2AuthenticationSuccessHandler()))
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(accessDeniedHandler()))
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
