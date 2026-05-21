package com.tad.gateway.auth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.tad.gateway.auth.entity.UserRole;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

	@Query("""
		select r.roleName
		from UserRole ur
		join Role r on r.id = ur.roleId
		where ur.userId = :userId
		order by ur.id asc
		""")
	List<String> findRoleNamesByUserId(@Param("userId") Long userId);
}
