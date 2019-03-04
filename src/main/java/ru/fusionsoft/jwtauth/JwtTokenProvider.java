package ru.fusionsoft.jwtauth;

import java.util.Map;

 interface JwtTokenProvider {
     String getJwtSecret();
     void setJwtSecret(String secret);

     void validateToken(String authToken) throws Exception;
     TokenData getTokenData(String token);
     String generateToken(String subject, Map<String, Object> claims);
     String generateToken(String subject, Map<String, Object> claims, Long exp);

     Long getJwtExpirationMs();

     void setJwtExpirationMs(Long ms);
}
