package com.sda.gf23spring.service;


import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.repository.PersonDao;
import com.sda.gf23spring.utils.Utils;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class PersonServiceImpl implements PersonService {
    private PersonDao personDao;

    public PersonServiceImpl(PersonDao personDao) {
        this.personDao = personDao;
    }

    @Override
    public List<Person> getAll() {
        return personDao.getAll();
    }

    @Override
    public Person getById(int personId) {
        return personDao.getById(personId);
    }

    @Override
    public List<Person> getByFistName(String firstName) {
        if (firstName == null || "".equals(firstName)) {
            return new ArrayList<>();
        }
        return personDao.getAll()
                .stream()
                .filter(x -> x.getFirstName().toLowerCase().contains(firstName.toLowerCase()))
                .collect(Collectors.toList());
    }

    @Override
    public List<Person> getByLastName(String lastName) {
        return personDao.getByLastName(lastName);
    }

    @Override
    public List<Person> getByBirthDateBetween(String from, String to, DateTimeFormatter format) {
        LocalDate dateFrom = checkString(from) ? LocalDate.parse(from, format) : LocalDate.of(1900, 01, 01);
        LocalDate dateTo = checkString(to) ? LocalDate.parse(to, format) : LocalDate.now();
        return personDao.getByBirthDateBetween(dateFrom, dateTo)
                .stream()
                .sorted(Comparator.comparing(Person::getBirthDate))
                .collect(Collectors.toList());
    }

    private boolean checkString(String txt) {
        return (txt != null && !txt.trim().equals(""));
    }

    @Override
    public List<Person> getBySalaryBetween(double from, double to) {
        return personDao.getBySalaryBetween(from, to);
    }

    @Override
    public List<Person> getByFirstNameAndLastName(String firstName, String lastName) {
        return getAll()
                .stream()
                .filter(x -> x.getFirstName().toLowerCase().contains(firstName.toLowerCase()))
                .filter(x -> x.getLastName().toLowerCase().contains(lastName.toLowerCase()))
                .collect(Collectors.toList());
    }

    @Override
    public Person add(Person person) {
        return personDao.add(person);
    }

    @Override
    public Person modify(int personId, Person person) {
        return personDao.modify(personId, person);
    }

    @Override
    public Person remove(int personId) {
        return personDao.remove(personId);
    }
}
