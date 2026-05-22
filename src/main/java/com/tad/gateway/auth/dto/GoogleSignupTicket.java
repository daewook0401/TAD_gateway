package com.tad.gateway.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GoogleSignupTicket {

    private String email;
    private String googleSubject;
    private String suggestedNickname;
    private String profileImageUrl;
}
