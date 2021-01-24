package com.sda.gf23spring.repository;

import com.sda.gf23spring.person.Person;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PersonDaoHibernate extends JpaRepository<Person,Integer> {
}
