package com.tad.gateway.auth.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SuccessResponse {

    private boolean success;
}
