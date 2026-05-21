package com.tad.gateway.auth.service;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailVerificationRedisService {

    private static final String CODE_PREFIX = "auth:email:code:";
    private static final String VERIFIED_PREFIX = "auth:email:verified:";

    private final StringRedisTemplate stringRedisTemplate;

    public void saveCode(String email, String code, Duration ttl) {
        stringRedisTemplate.opsForValue().set(codeKey(email), code, ttl);
    }

    public String getCode(String email) {
        return stringRedisTemplate.opsForValue().get(codeKey(email));
    }

    public void markVerified(String email, Duration ttl) {
        stringRedisTemplate.opsForValue().set(verifiedKey(email), "true", ttl);
    }

    public boolean isVerified(String email) {
        return "true".equals(stringRedisTemplate.opsForValue().get(verifiedKey(email)));
    }

    public void clearCode(String email) {
        stringRedisTemplate.delete(codeKey(email));
    }

    public void clear(String email) {
        stringRedisTemplate.delete(codeKey(email));
        stringRedisTemplate.delete(verifiedKey(email));
    }

    private String codeKey(String email) {
        return CODE_PREFIX + email;
    }

    private String verifiedKey(String email) {
        return VERIFIED_PREFIX + email;
    }
}
