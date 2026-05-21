package com.tad.gateway.auth.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.tad.gateway.auth.entity.Role;
import com.tad.gateway.auth.repository.RoleRepository;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class AuthDataInitializer implements ApplicationRunner {

	private final RoleRepository roleRepository;

	@Override
	@Transactional
	public void run(ApplicationArguments args) {
		ensureRole("ROLE_USER", "일반 사용자");
		ensureRole("ROLE_ADMIN", "관리자");
	}

	private void ensureRole(String roleName, String description) {
		roleRepository.findByRoleName(roleName)
			.orElseGet(() -> roleRepository.save(Role.builder()
				.roleName(roleName)
				.description(description)
				.build()));
	}
}
