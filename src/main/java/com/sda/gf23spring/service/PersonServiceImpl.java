package com.sda.gf23spring.service;


import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.repository.PersonDao;
import com.sda.gf23spring.repository.PersonDaoHibernate;
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
    PersonDaoHibernate personDaoHibernate;

    public PersonServiceImpl(PersonDaoHibernate personDaoHibernate) {
        this.personDaoHibernate = personDaoHibernate;
    }

    @Override
    public List<Person> getAll() {
        return personDaoHibernate.findAll();
    }

    @Override
    public Person getById(int personId) {
        return personDaoHibernate.getOne(personId);
    }

    @Override
    public List<Person> getByFistName(String firstName) {
        if (firstName == null || "".equals(firstName)) {
            return new ArrayList<>();
        }
        return getAll()
                .stream()
                .filter(x -> x.getFirstName().toLowerCase().contains(firstName.toLowerCase()))
                .collect(Collectors.toList());
    }

    @Override
    public List<Person> getByLastName(String lastName) {
        return personDaoHibernate.getAllByLastName(lastName);
    }

    @Override
    public List<Person> getByBirthDateBetween(String from, String to, DateTimeFormatter format) {
        LocalDate dateFrom = checkString(from) ? LocalDate.parse(from, format) : LocalDate.of(1900, 01, 01);
        LocalDate dateTo = checkString(to) ? LocalDate.parse(to, format) : LocalDate.now();
        return personDaoHibernate.getAllByBirthDateBetween(dateFrom, dateTo);
    }

    private boolean checkString(String txt) {
        return (txt != null && !txt.trim().equals(""));
    }

    @Override
    public List<Person> getBySalaryBetween(double from, double to) {
        return personDaoHibernate.getAllBySalaryBetween(from, to);
    }

    @Override
    public List<Person> getByFirstNameAndLastName(String firstName, String lastName) {
        return personDaoHibernate.pobierz(firstName, lastName);
    }

    @Override
    public Person add(Person person) {
        return personDaoHibernate.save(person);
    }

    @Override
    public Person modify(int personId, Person person) {
        person.setPersonId(personId);
        return personDaoHibernate.save(person);
    }

    @Override
    public Person remove(int personId) {
        Person byId = getById(personId);
        personDaoHibernate.delete(byId);
        return byId;
    }
}