package ru.fusionsoft.jwtauth;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Date;
import java.util.Map;

public abstract class JwtBaseTokenProvider implements JwtTokenProvider{
    private String jwtSecret;

    private Long jwtExpirationMs;

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    public String generateToken(String subject, Map<String, Object> claims) {
        return generateToken(subject, claims, System.currentTimeMillis() + getJwtExpirationMs());
    }

    public String generateToken(String subject, Map<String, Object> claims, Long exp) {
        Date now = new Date();
        Date expiryDate = new Date(exp);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, getJwtSecret())
                .setHeaderParam("typ", "JWT")
                .compact();
    }

    public TokenData getTokenData(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(getJwtSecret())
                .parseClaimsJws(token)
                .getBody();

        return new TokenData(token, claims);
    }

    public void validateToken(String authToken) throws Exception {
        Jwts.parser().setSigningKey(getJwtSecret()).parseClaimsJws(authToken);
    }

    public Logger getLogger() {
        return logger;
    }

    public String getJwtSecret() {
        return jwtSecret;
    }

    public void setJwtSecret(String jwtSecret) {
        this.jwtSecret = jwtSecret;
    }

    public Long getJwtExpirationMs() {
        return jwtExpirationMs;
    }

    public void setJwtExpirationMs(Long jwtExpirationMs) {
        this.jwtExpirationMs = jwtExpirationMs;
    }
}
