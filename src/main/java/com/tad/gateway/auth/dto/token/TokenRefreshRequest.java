package com.tad.gateway.auth.dto.token;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class TokenRefreshRequest {

    @NotBlank(message = "INVALID_REFRESH_TOKEN")
    private String refreshToken;
}
