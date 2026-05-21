package com.tad.gateway.security.jwt;

import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtil {
    @Value("${app.jwt.secret-base64}")
    private String secretKey;

    @Value("${app.jwt.access-minutes}")
    private int accessTokenMinutes;

    @Value("${app.jwt.refresh-minutes}")
    private int refreshTokenMinutes;

    @Value("${app.jwt.issuer}")
    private String issuer;

    private SecretKey key;

    @PostConstruct
    public void init(){
        try {
            byte[] keyArr = Base64.getDecoder().decode(secretKey);
            this.key = Keys.hmacShaKeyFor(keyArr);
        } catch (Exception e) {
            throw new IllegalStateException("JWT secret key initialization failed", e);
        }
    }

    public String getAccessToken(String publicId, List<String> roles){
        return Jwts.builder()
                    .subject(publicId)
                    .issuer(issuer)
                    .claim("type", "access")
                    .claim("roles", roles)
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + (accessTokenMinutes * 60 * 1000L)))
                    .signWith(key)
                    .compact();
    }

    public String getRefreshToken(String publicId, List<String> roles){
        return Jwts.builder()
                    .subject(publicId)
                    .issuer(issuer)
                    .claim("type", "refresh")
                    .claim("roles", roles)
                    .issuedAt(new Date())
                    .expiration(new Date(System.currentTimeMillis() + (refreshTokenMinutes * 60 * 1000L)))
                    .signWith(key)
                    .compact();
    }

    public int getRefreshTokenMinutes() {
        return refreshTokenMinutes;
    }

    public Claims parseJwt(String token){
        try{
            return Jwts.parser()
                                .verifyWith(key)
                                .requireIssuer(issuer)
                                .build()
                                .parseSignedClaims(token)
                                .getPayload();
        } catch (ExpiredJwtException e){
            log.warn("JWT token expired: {}", e.getMessage());
            throw new IllegalArgumentException("EXPIRED", e);
        } catch (JwtException e){
            log.warn("Invalid JWT token: {}", e.getMessage());
            throw new IllegalArgumentException("INVALID", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            parseJwt(token);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
