package com.tad.gateway.auth.service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tad.gateway.auth.dto.GoogleSignupTicket;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class GoogleSignupRedisService {

    private static final String PREFIX = "auth:google-signup:";
    private static final int TOKEN_BYTES = 32;

    private final StringRedisTemplate stringRedisTemplate;
    private final ObjectMapper objectMapper;
    private final SecureRandom secureRandom = new SecureRandom();

    public String save(GoogleSignupTicket ticket, Duration ttl) {
        String token = generateToken();
        try {
            stringRedisTemplate.opsForValue().set(key(token), objectMapper.writeValueAsString(ticket), ttl);
            return token;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Google 가입 정보를 저장할 수 없습니다.", e);
        }
    }

    public GoogleSignupTicket get(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }

        String value = stringRedisTemplate.opsForValue().get(key(token.trim()));
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return objectMapper.readValue(value, GoogleSignupTicket.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Google 가입 정보를 읽을 수 없습니다.", e);
        }
    }

    public void delete(String token) {
        if (token != null && !token.isBlank()) {
            stringRedisTemplate.delete(key(token.trim()));
        }
    }

    private String generateToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String key(String token) {
        return PREFIX + token;
    }
}
