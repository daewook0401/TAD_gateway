package com.tad.gateway.auth.dto.response;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.tad.gateway.auth.entity.User;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenIntrospectionResponse {

    private boolean active;
    private String message;
    private Long userId;
    private String email;
    private String nickname;
    private String profileImageUrl;
    private String status;
    private List<String> roles;

    public static TokenIntrospectionResponse active(User user, List<String> roles) {
        return TokenIntrospectionResponse.builder()
            .active(true)
            .userId(user.getId())
            .email(user.getEmail())
            .nickname(user.getNickname())
            .profileImageUrl(user.getProfileImageUrl())
            .status(user.getStatus())
            .roles(roles)
            .build();
    }

    public static TokenIntrospectionResponse inactive(String message) {
        return TokenIntrospectionResponse.builder()
            .active(false)
            .message(message)
            .build();
    }
}
