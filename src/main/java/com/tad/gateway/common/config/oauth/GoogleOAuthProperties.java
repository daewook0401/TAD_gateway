package com.tad.gateway.common.config.oauth;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.oauth2.google")
public class GoogleOAuthProperties {

    private String clientId;

    public boolean hasClientId() {
        return clientId != null && !clientId.isBlank();
    }
}
