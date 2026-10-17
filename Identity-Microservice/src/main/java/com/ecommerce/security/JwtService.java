package com.ecommerce.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final SecretKey secretKey;
    public JwtService(@Value("${jwt.secret}") String secretKey) {
        byte[] decodedKey = Decoders.BASE64.decode(secretKey);
        this.secretKey = Keys.hmacShaKeyFor(decodedKey);
    }

    public String generateToken(
            Long userId,
            String userEmail,
            List<String> roles) {
        return Jwts.builder()
                .subject(userEmail)
                .claim("userId", userId)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(
                        System.currentTimeMillis() + 3600000
                ))
                .signWith(secretKey)
                .compact();
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
    public String extractUserEmail(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public Long extractUserId(String token) {
        Claims claims = getClaims(token);
        return claims.get("userId", Long.class);
    }

    public List<String> extractRoles(String token) {
        Claims claims = getClaims(token);
        return claims.get("roles", List.class);
    }

    public boolean isTokenValid(String token) {
        try {
            getClaims(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

}
