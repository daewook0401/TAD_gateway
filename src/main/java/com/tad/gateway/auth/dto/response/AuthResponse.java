package com.tad.gateway.auth.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    private boolean success;
    private String message;
    private AuthUserResponse user;
    private String accessToken;
    private String refreshToken;
    private Boolean registrationRequired;
    private String registrationToken;
    private String email;
    private String nickname;
    private String profileImageUrl;

    public AuthResponse withoutRefreshToken() {
        return AuthResponse.builder()
            .success(success)
            .message(message)
            .user(user)
            .accessToken(accessToken)
            .registrationRequired(registrationRequired)
            .registrationToken(registrationToken)
            .email(email)
            .nickname(nickname)
            .profileImageUrl(profileImageUrl)
            .build();
    }
}
