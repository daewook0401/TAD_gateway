package com.tad.gateway.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.tad.gateway.auth.dto.token.TokenResponse;
import com.tad.gateway.auth.repository.UserRoleRepository;
import com.tad.gateway.auth.repository.UserRepository;
import com.tad.gateway.security.jwt.JwtUtil;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JwtRefreshService {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;

    public TokenResponse rotateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("INVALID_REFRESH_TOKEN");
        }

        refreshToken = refreshToken.trim();

        Claims claims = jwtUtil.parseJwt(refreshToken);
        if (!"refresh".equals(claims.get("type", String.class))) {
            throw new IllegalArgumentException("INVALID_REFRESH_TOKEN");
        }

        UUID publicId = UUID.fromString(claims.getSubject());
        Long userId = refreshTokenRedisService.getUserId(publicId);
        if (userId == null || !userRepository.existsById(userId)) {
            throw new IllegalArgumentException("INVALID_REFRESH_TOKEN");
        }

        String savedRefreshToken = refreshTokenRedisService.getRefreshToken(publicId);
        if (savedRefreshToken == null || !sameToken(savedRefreshToken, refreshToken)) {
            refreshTokenRedisService.delete(publicId);
            throw new IllegalArgumentException("INVALID_REFRESH_TOKEN");
        }

        refreshTokenRedisService.delete(publicId);

        List<String> roles = userRoleRepository.findRoleNamesByUserId(userId);
        String newAccessToken = jwtUtil.getAccessToken(publicId.toString(), roles);
        String newRefreshToken = jwtUtil.getRefreshToken(publicId.toString(), roles);

        refreshTokenRedisService.save(
            publicId,
            userId,
            newRefreshToken,
            Duration.ofMinutes(jwtUtil.getRefreshTokenMinutes())
        );

        return TokenResponse.builder()
            .accessToken(newAccessToken)
            .refreshToken(newRefreshToken)
            .tokenType("Bearer")
            .build();
    }

    private boolean sameToken(String left, String right) {
        return MessageDigest.isEqual(
            left.getBytes(StandardCharsets.UTF_8),
            right.getBytes(StandardCharsets.UTF_8)
        );
    }
}
