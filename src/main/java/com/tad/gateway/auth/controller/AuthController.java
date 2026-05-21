package com.tad.gateway.auth.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tad.gateway.auth.dto.request.ChangePasswordRequest;
import com.tad.gateway.auth.dto.request.GoogleLoginRequest;
import com.tad.gateway.auth.dto.request.LoginRequest;
import com.tad.gateway.auth.dto.request.LogoutRequest;
import com.tad.gateway.auth.dto.request.MailSendRequest;
import com.tad.gateway.auth.dto.request.MailVerifyRequest;
import com.tad.gateway.auth.dto.request.SignupRequest;
import com.tad.gateway.auth.dto.request.UpdateProfileRequest;
import com.tad.gateway.auth.dto.response.AuthResponse;
import com.tad.gateway.auth.dto.response.MailVerificationResponse;
import com.tad.gateway.auth.dto.response.ProfileResponse;
import com.tad.gateway.auth.dto.response.SuccessResponse;
import com.tad.gateway.auth.dto.token.TokenRefreshRequest;
import com.tad.gateway.auth.dto.token.TokenResponse;
import com.tad.gateway.auth.entity.User;
import com.tad.gateway.auth.service.AuthService;
import com.tad.gateway.auth.service.JwtRefreshService;
import com.tad.gateway.auth.service.MailService;
import com.tad.gateway.auth.service.RefreshTokenCookieService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

	private final MailService mailService;
	private final JwtRefreshService jwtRefreshService;
	private final AuthService authService;
	private final RefreshTokenCookieService refreshTokenCookieService;

	@PostMapping("/mail")
	public ResponseEntity<MailVerificationResponse> sendMail(@Valid @RequestBody MailSendRequest request) {
		return ResponseEntity.ok(mailService.sendMail(request.getEmail()));
	}

	@PostMapping("/mail/verify")
	public ResponseEntity<MailVerificationResponse> verifyMail(@Valid @RequestBody MailVerifyRequest request) {
		return ResponseEntity.ok(mailService.verify(request.getEmail(), request.getCode()));
	}

	@PostMapping("/signup")
	public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request) {
		return ResponseEntity.status(HttpStatus.CREATED).body(authService.signup(request));
	}

	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
		AuthResponse response = authService.login(request);
		return ResponseEntity.ok()
			.headers(refreshTokenCookieService.headersWithRefreshCookie(response.getRefreshToken()))
			.body(response.withoutRefreshToken());
	}

	@PostMapping("/logout")
	public ResponseEntity<SuccessResponse> logout(
		@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
		@CookieValue(value = RefreshTokenCookieService.COOKIE_NAME, required = false) String refreshTokenCookie,
		@RequestBody(required = false) LogoutRequest request
	) {
		String refreshToken = refreshTokenCookie != null ? refreshTokenCookie : request == null ? null : request.getRefreshToken();
		SuccessResponse response = authService.logout(authorization, refreshToken);
		return ResponseEntity.ok()
			.headers(refreshTokenCookieService.headersClearingRefreshCookie())
			.body(response);
	}

	@GetMapping("/me")
	public ResponseEntity<ProfileResponse> getMyProfile(@AuthenticationPrincipal User currentUser) {
		return ResponseEntity.ok(authService.getMyProfile(currentUser));
	}

	@PutMapping("/me")
	public ResponseEntity<ProfileResponse> updateMyProfile(
		@AuthenticationPrincipal User currentUser,
		@Valid @RequestBody UpdateProfileRequest request
	) {
		return ResponseEntity.ok(authService.updateMyProfile(currentUser, request));
	}

	@PutMapping("/me/password")
	public ResponseEntity<SuccessResponse> changePassword(
		@AuthenticationPrincipal User currentUser,
		@Valid @RequestBody ChangePasswordRequest request
	) {
		return ResponseEntity.ok(authService.changePassword(currentUser, request));
	}

	@PostMapping("/google-login")
	public ResponseEntity<AuthResponse> googleLogin(@Valid @RequestBody GoogleLoginRequest request) {
		return ResponseEntity.ok(authService.googleLogin(request.getToken()));
	}

	@PostMapping("/refresh")
	public ResponseEntity<TokenResponse> refresh(
		@CookieValue(value = RefreshTokenCookieService.COOKIE_NAME, required = false) String refreshTokenCookie,
		@RequestBody(required = false) TokenRefreshRequest request
	) {
		String refreshToken = refreshTokenCookie != null ? refreshTokenCookie : request == null ? null : request.getRefreshToken();
		TokenResponse response = jwtRefreshService.rotateRefreshToken(refreshToken);
		return ResponseEntity.ok()
			.headers(refreshTokenCookieService.headersWithRefreshCookie(response.getRefreshToken()))
			.body(response.withoutRefreshToken());
	}
}
