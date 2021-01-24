package com.sda.gf23spring.repository;

import com.sda.gf23spring.person.Person;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDate;
import java.util.List;

public interface PersonDaoHibernate extends JpaRepository<Person,Integer> {
    List<Person> getAllByLastName(String lastName);
    List<Person> getAllByBirthDateBetween(LocalDate min,LocalDate max);
    List<Person> getAllBySalaryBetween(double min,double max);
}
