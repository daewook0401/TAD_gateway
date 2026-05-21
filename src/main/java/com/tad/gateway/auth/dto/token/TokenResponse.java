package com.tad.gateway.auth.dto.token;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TokenResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType;

    public TokenResponse withoutRefreshToken() {
        return TokenResponse.builder()
            .accessToken(accessToken)
            .tokenType(tokenType)
            .build();
    }
}
