package com.tad.gateway.auth.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class MailVerificationResponse {

    private boolean success;
    private String message;
    private String email;
    private boolean verified;
}
