package com.tad.gateway.common.config.mail;

import java.util.Properties;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.mail.MailProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

@Configuration
@EnableConfigurationProperties(MailProperties.class)
public class MailConfig {

    @Bean
    @ConditionalOnMissingBean(JavaMailSender.class)
    public JavaMailSender javaMailSender(MailProperties mailProperties) {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();

        if (mailProperties.getHost() != null) {
            mailSender.setHost(mailProperties.getHost());
        }
        if (mailProperties.getPort() != null) {
            mailSender.setPort(mailProperties.getPort());
        }
        if (mailProperties.getUsername() != null) {
            mailSender.setUsername(mailProperties.getUsername());
        }
        if (mailProperties.getPassword() != null) {
            mailSender.setPassword(mailProperties.getPassword());
        }
        if (mailProperties.getProtocol() != null) {
            mailSender.setProtocol(mailProperties.getProtocol());
        }
        if (mailProperties.getDefaultEncoding() != null) {
            mailSender.setDefaultEncoding(mailProperties.getDefaultEncoding().name());
        }

        Properties javaMailProperties = new Properties();
        javaMailProperties.putAll(mailProperties.getProperties());
        mailSender.setJavaMailProperties(javaMailProperties);

        return mailSender;
    }
}
