package com.sda.gf23spring.repository;

import com.sda.gf23spring.person.UserRole;
import com.sda.gf23spring.person.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleDao extends JpaRepository<UserRole, UserRoleId> {
}
