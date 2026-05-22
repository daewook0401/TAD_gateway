package com.tad.gateway.auth.dto.request;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GoogleSignupRequest {

    @NotBlank(message = "Google 가입 토큰이 필요합니다.")
    private String registrationToken;

    @NotBlank(message = "닉네임은 필수입니다.")
    @Size(min = 2, max = 20, message = "닉네임은 2자 이상 20자 이하여야 합니다.")
    private String nickname;

    @AssertTrue(message = "이용약관에 동의해주세요.")
    private boolean termsAccepted;
}
