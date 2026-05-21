package com.tad.gateway.auth.service;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import com.tad.gateway.security.jwt.JwtUtil;

@Service
public class RefreshTokenCookieService {

	public static final String COOKIE_NAME = "refreshToken";

	private final JwtUtil jwtUtil;

	@Value("${app.auth.refresh-cookie.path:/api/auth}")
	private String cookiePath;

	@Value("${app.auth.refresh-cookie.secure:false}")
	private boolean secure;

	@Value("${app.auth.refresh-cookie.same-site:Lax}")
	private String sameSite;

	public RefreshTokenCookieService(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	public String createCookieHeader(String refreshToken) {
		return ResponseCookie.from(COOKIE_NAME, refreshToken)
			.httpOnly(true)
			.secure(secure)
			.sameSite(sameSite)
			.path(cookiePath)
			.maxAge(Duration.ofMinutes(jwtUtil.getRefreshTokenMinutes()))
			.build()
			.toString();
	}

	public String clearCookieHeader() {
		return ResponseCookie.from(COOKIE_NAME, "")
			.httpOnly(true)
			.secure(secure)
			.sameSite(sameSite)
			.path(cookiePath)
			.maxAge(Duration.ZERO)
			.build()
			.toString();
	}

	public HttpHeaders headersWithRefreshCookie(String refreshToken) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.SET_COOKIE, createCookieHeader(refreshToken));
		return headers;
	}

	public HttpHeaders headersClearingRefreshCookie() {
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.SET_COOKIE, clearCookieHeader());
		return headers;
	}
}
