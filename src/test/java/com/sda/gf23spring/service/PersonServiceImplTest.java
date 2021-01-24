package com.sda.gf23spring.service;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.repository.PersonDao;
import com.sda.gf23spring.repository.PersonDaoHibernate;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.List;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PersonServiceImplTest {

    private PersonDaoHibernate personDao = mock(PersonDaoHibernate.class);
    private PersonService personService;

    @BeforeEach
    void setUp() {
        Person p1 = new Person("Ada", "Nowak", LocalDate.of(1992,03,02), 1234.12);
        p1.setPersonId(1);
        Person p2 = new Person("Julia", "Kwiatkowska", LocalDate.of(1981,06,02), 2234.12);
        p2.setPersonId(2);
        List<Person> personList = List.of(p1, p2);
        personService = new PersonServiceImpl(personDao);
        when(personDao.findAll()).thenReturn(personList);
    }

    @Test
    void getAll() {
    }

    @Test
    void getById() {
    }

    @Test
    void getByFistName() {
        Assertions.assertThat(personService.getByFistName("ada").get(0).getPersonId()).isEqualTo(1);
    }

    @Test
    void getByLastName() {
    }

    @Test
    void getByBirthDateBetween() {
    }

    @Test
    void getBySalaryBetween() {
    }

    @Test
    void add() {
    }

    @Test
    void modify() {
    }

    @Test
    void remove() {
    }
}