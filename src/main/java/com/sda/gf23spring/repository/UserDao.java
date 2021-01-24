package com.sda.gf23spring.repository;

import com.sda.gf23spring.person.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User,String> {
}
