package com.example.springsecurity.jwt;

public class JwtAuthentication {

    public final String token;

    public final String username;

    JwtAuthentication(String token, String username) {
        checkToken(token);
        checkUsername(username);

        this.token = token;
        this.username = username;
    }

    private void checkToken(String token) {
        if (token == null) {
            throw new IllegalArgumentException("token must be provided.");
        }
    }

    private void checkUsername(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must be provided.");
        }
    }
}
