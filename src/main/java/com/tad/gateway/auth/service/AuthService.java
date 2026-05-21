package com.tad.gateway.auth.service;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tad.gateway.auth.dto.request.ChangePasswordRequest;
import com.tad.gateway.auth.dto.request.LoginRequest;
import com.tad.gateway.auth.dto.request.SignupRequest;
import com.tad.gateway.auth.dto.request.UpdateProfileRequest;
import com.tad.gateway.auth.dto.response.AuthResponse;
import com.tad.gateway.auth.dto.response.AuthUserResponse;
import com.tad.gateway.auth.dto.response.ProfileResponse;
import com.tad.gateway.auth.dto.response.SuccessResponse;
import com.tad.gateway.auth.entity.UserRole;
import com.tad.gateway.auth.repository.RoleRepository;
import com.tad.gateway.auth.repository.UserRoleRepository;
import com.tad.gateway.auth.entity.User;
import com.tad.gateway.auth.repository.UserRepository;
import com.tad.gateway.security.jwt.JwtUtil;
import com.tad.gateway.common.util.TextUtils;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final EmailVerificationRedisService emailVerificationRedisService;
    private final LoginHistoryService loginHistoryService;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;

    @Transactional
    public AuthResponse signup(SignupRequest request) {
        String normalizedEmail = normalizeEmail(request.getEmail());
        String normalizedNickname = request.getNickname().trim();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalArgumentException("이미 가입된 이메일입니다.");
        }

        if (userRepository.existsByNickname(normalizedNickname)) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }

        if (!emailVerificationRedisService.isVerified(normalizedEmail)) {
            throw new IllegalArgumentException("이메일 인증을 완료해주세요.");
        }

        User user = User.builder()
            .email(normalizedEmail)
            .nickname(normalizedNickname)
            .passwordHash(passwordEncoder.encode(request.getPassword()))
            .emailVerified(true)
            .status("ACTIVE")
            .build();

        User savedUser = userRepository.save(user);
        Long roleId = roleRepository.findByRoleName("ROLE_USER")
            .orElseThrow(() -> new IllegalStateException("기본 권한 ROLE_USER가 존재하지 않습니다."))
            .getId();

        userRoleRepository.save(UserRole.builder()
            .userId(savedUser.getId())
            .roleId(roleId)
            .build());

        List<String> roles = userRoleRepository.findRoleNamesByUserId(savedUser.getId());
        emailVerificationRedisService.clear(normalizedEmail);

        return AuthResponse.builder()
            .success(true)
            .message("회원가입이 완료되었습니다.")
            .user(AuthUserResponse.from(savedUser, roles))
            .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        String normalizedEmail = normalizeEmail(request.getEmail());
        User user = userRepository.findByEmail(normalizedEmail)
            .orElseThrow(() -> new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다."));

        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            saveLoginHistory(user.getId(), "NORMAL", "FAILURE");
            throw new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            saveLoginHistory(user.getId(), "NORMAL", "BLOCKED");
            throw new IllegalArgumentException("비활성화된 계정입니다.");
        }

        user.setLastLoginAt(OffsetDateTime.now());
        saveLoginHistory(user.getId(), "NORMAL", "SUCCESS");
        List<String> roles = userRoleRepository.findRoleNamesByUserId(user.getId());

        UUID publicId = UUID.randomUUID();
        String accessToken = jwtUtil.getAccessToken(publicId.toString(), roles);
        String refreshToken = jwtUtil.getRefreshToken(publicId.toString(), roles);

        refreshTokenRedisService.save(
            publicId,
            user.getId(),
            refreshToken,
            Duration.ofMinutes(jwtUtil.getRefreshTokenMinutes())
        );

        return AuthResponse.builder()
            .success(true)
            .user(AuthUserResponse.from(user, roles))
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
    }

    public SuccessResponse logout(String authorization, String refreshToken) {
        resolvePublicId(authorization, refreshToken)
            .ifPresent(refreshTokenRedisService::delete);

        return SuccessResponse.builder()
            .success(true)
            .build();
    }

    @Transactional(readOnly = true)
    public ProfileResponse getMyProfile(User currentUser) {
        User user = userRepository.findById(currentUser.getId())
            .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));
        List<String> roles = userRoleRepository.findRoleNamesByUserId(user.getId());
        return ProfileResponse.from(user, roles);
    }

    @Transactional
    public ProfileResponse updateMyProfile(User currentUser, UpdateProfileRequest request) {
        User user = userRepository.findById(currentUser.getId())
            .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        String normalizedNickname = request.getNickname().trim();
        if (userRepository.existsByNicknameAndIdNot(normalizedNickname, user.getId())) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }

        user.setNickname(normalizedNickname);
        List<String> roles = userRoleRepository.findRoleNamesByUserId(user.getId());
        return ProfileResponse.from(user, roles);
    }

    @Transactional
    public SuccessResponse changePassword(User currentUser, ChangePasswordRequest request) {
        User user = userRepository.findById(currentUser.getId())
            .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        if (user.getPasswordHash() == null || !passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("현재 비밀번호가 올바르지 않습니다.");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("새 비밀번호는 현재 비밀번호와 달라야 합니다.");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        return SuccessResponse.builder()
            .success(true)
            .build();
    }

    public AuthResponse googleLogin(String credentialToken) {
        if (credentialToken == null || credentialToken.isBlank()) {
            throw new IllegalArgumentException("INVALID_GOOGLE_TOKEN");
        }

        throw new UnsupportedOperationException("GOOGLE_LOGIN_NOT_ENABLED");
    }

    private String normalizeEmail(String email) {
        return TextUtils.normalizeNullableLowerCase(email);
    }

    private java.util.Optional<UUID> resolvePublicId(String authorization, String refreshToken) {
        java.util.Optional<UUID> accessPublicId = extractPublicIdFromAuthorization(authorization);
        if (accessPublicId.isPresent()) {
            return accessPublicId;
        }

        return extractPublicIdFromToken(refreshToken, "refresh");
    }

    private java.util.Optional<UUID> extractPublicIdFromAuthorization(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return java.util.Optional.empty();
        }

        return extractPublicIdFromToken(authorization.substring(7), "access");
    }

    private java.util.Optional<UUID> extractPublicIdFromToken(String token, String expectedType) {
        if (token == null || token.isBlank()) {
            return java.util.Optional.empty();
        }

        try {
            Claims claims = jwtUtil.parseJwt(token.trim());
            if (!expectedType.equals(claims.get("type", String.class))) {
                return java.util.Optional.empty();
            }

            return java.util.Optional.of(UUID.fromString(claims.getSubject()));
        } catch (RuntimeException e) {
            return java.util.Optional.empty();
        }
    }

    private void saveLoginHistory(Long userId, String loginType, String loginResult) {
        HttpServletRequest request = currentRequest();
        loginHistoryService.record(
            userId,
            loginType,
            loginResult,
            resolveClientIp(request),
            resolveUserAgent(request)
        );
    }

    private HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes servletRequestAttributes) {
            return servletRequestAttributes.getRequest();
        }
        return null;
    }

    private String resolveClientIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }

        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }

        return request.getRemoteAddr();
    }

    private String resolveUserAgent(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        String userAgent = request.getHeader("User-Agent");
        if (userAgent == null || userAgent.isBlank()) {
            return null;
        }

        return userAgent;
    }
}
