package com.tad.gateway.auth.dto.response;

import java.util.List;

import com.tad.gateway.auth.entity.User;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthUserResponse {

    private Long id;
    private String nickname;
    private String email;
    private String memberRole;
    private Boolean passwordLoginEnabled;
    private List<String> roles;

    public static AuthUserResponse from(User user, List<String> roles) {
        String memberRole = roles == null || roles.isEmpty() ? null : roles.get(0);
        return AuthUserResponse.builder()
            .id(user.getId())
            .nickname(user.getNickname())
            .email(user.getEmail())
            .memberRole(memberRole)
            .passwordLoginEnabled(user.getPasswordHash() != null && !user.getPasswordHash().isBlank())
            .roles(roles)
            .build();
    }
}
