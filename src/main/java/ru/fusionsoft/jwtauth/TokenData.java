package ru.fusionsoft.jwtauth;

import io.jsonwebtoken.Claims;

public class TokenData {
    private String token;
    private Claims claims;

    public TokenData(String token, Claims claims) {
        this.token = token;
        this.claims = claims;
    }

    public String getToken() {
        return token;
    }

    public Claims getClaims() {
        return claims;
    }
}
