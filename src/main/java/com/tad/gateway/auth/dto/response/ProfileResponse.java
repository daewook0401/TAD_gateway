package com.tad.gateway.auth.dto.response;

import java.time.OffsetDateTime;
import java.util.List;

import com.tad.gateway.auth.entity.User;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ProfileResponse {

    private Long id;
    private String nickname;
    private String email;
    private Boolean emailVerified;
    private Boolean passwordLoginEnabled;
    private List<String> roles;
    private OffsetDateTime createdAt;
    private OffsetDateTime lastLoginAt;

    public static ProfileResponse from(User user, List<String> roles) {
        return ProfileResponse.builder()
            .id(user.getId())
            .nickname(user.getNickname())
            .email(user.getEmail())
            .emailVerified(user.getEmailVerified())
            .passwordLoginEnabled(user.getPasswordHash() != null && !user.getPasswordHash().isBlank())
            .roles(roles)
            .createdAt(user.getCreatedAt())
            .lastLoginAt(user.getLastLoginAt())
            .build();
    }
}
