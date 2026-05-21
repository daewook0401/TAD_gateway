package com.tad.gateway.auth.service;

import java.time.Duration;
import java.util.UUID;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenRedisService {

    private static final String REFRESH_PREFIX = "auth:refresh:";
    private static final String SESSION_PREFIX = "auth:session:";

    private final StringRedisTemplate stringRedisTemplate;

    public void save(UUID publicId, Long userId, String refreshToken, Duration ttl) {
        stringRedisTemplate.opsForValue().set(refreshKey(publicId), refreshToken, ttl);
        stringRedisTemplate.opsForValue().set(sessionKey(publicId), String.valueOf(userId), ttl);
    }

    public String getRefreshToken(UUID publicId) {
        return stringRedisTemplate.opsForValue().get(refreshKey(publicId));
    }

    public Long getUserId(UUID publicId) {
        String value = stringRedisTemplate.opsForValue().get(sessionKey(publicId));
        if (value == null || value.isBlank()) {
            return null;
        }
        return Long.valueOf(value);
    }

    public void delete(UUID publicId) {
        stringRedisTemplate.delete(refreshKey(publicId));
        stringRedisTemplate.delete(sessionKey(publicId));
    }

    private String refreshKey(UUID publicId) {
        return REFRESH_PREFIX + publicId;
    }

    private String sessionKey(UUID publicId) {
        return SESSION_PREFIX + publicId;
    }
}
