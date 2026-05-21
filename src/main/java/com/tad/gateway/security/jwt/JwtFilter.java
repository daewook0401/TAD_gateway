package com.tad.gateway.security.jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.tad.gateway.auth.service.RefreshTokenRedisService;
import com.tad.gateway.auth.repository.UserRepository;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RefreshTokenRedisService refreshTokenRedisService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getServletPath();
        String method = request.getMethod();

        if (isRefreshPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7);

            try {
                Claims claims = jwtUtil.parseJwt(token);
                if (!"access".equals(claims.get("type", String.class))) {
                    throw new IllegalArgumentException("INVALID");
                }

                UUID publicId = UUID.fromString(claims.getSubject());
                Long userId = refreshTokenRedisService.getUserId(publicId);
                if (userId == null) {
                    throw new IllegalArgumentException("INVALID");
                }

                var user = userRepository.findById(userId).orElse(null);
                if (user == null) {
                    throw new IllegalArgumentException("INVALID");
                }

                List<?> roleClaims = claims.get("roles", List.class);
                List<SimpleGrantedAuthority> authorities = roleClaims == null
                    ? List.of()
                    : roleClaims.stream()
                        .filter(String.class::isInstance)
                        .map(String.class::cast)
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                        user,
                        null,
                        authorities
                    );

                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (RuntimeException e) {
                SecurityContextHolder.clearContext();

                if (isPublicPath(path, method)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                writeUnauthorizedResponse(response, "EXPIRED".equals(e.getMessage())
                    ? "ACCESS_TOKEN_EXPIRED"
                    : "INVALID_TOKEN");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRefreshPath(String path) {
        return "/auth/refresh".equals(path);
    }

    private boolean isPublicPath(String path, String method) {
        return (("POST".equalsIgnoreCase(method)) && (
                "/auth/login".equals(path)
                    || "/auth/signup".equals(path)
                    || "/auth/logout".equals(path)
                    || "/auth/refresh".equals(path)
                    || "/auth/introspect".equals(path)
                    || "/auth/mail".equals(path)
                    || "/auth/mail/verify".equals(path)
                    || "/auth/google-login".equals(path)
            ))
            || "/health".equals(path)
            || path.startsWith("/actuator/");
    }

    private void writeUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(Map.of(
            "success", false,
            "message", message
        )));
    }
}
