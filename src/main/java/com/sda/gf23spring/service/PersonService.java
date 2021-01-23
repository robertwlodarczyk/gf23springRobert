package com.sda.gf23spring.service;

import com.sda.gf23spring.person.Person;

import java.time.format.DateTimeFormatter;
import java.util.List;

public interface PersonService {
    List<Person> getAll();
    Person getById(int personId);
    List<Person> getByFistName(String firstName);
    List<Person> getByLastName(String lastName);
    List<Person> getByBirthDateBetween(String from, String to, DateTimeFormatter format);
    List<Person> getBySalaryBetween(double from, double to);
    List<Person> getByFirstNameAndLastName(String firstName, String lastName);

    Person add(Person person);
    Person modify(int personId, Person person);
    Person remove(int personId);
}
