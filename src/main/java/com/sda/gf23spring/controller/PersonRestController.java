package com.sda.gf23spring.controller;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.service.PersonService;
import com.sda.gf23spring.utils.Utils;
import org.slf4j.Logger;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
public class PersonRestController {
    PersonService personService;
    Logger logger;

    public PersonRestController(PersonService personService, Logger logger) {
        this.personService = personService;
        this.logger = logger;
    }

    @GetMapping("/persons")
    public List<Person> getAllPerson() {
        logger.debug("Get all Persons");
        return personService.getAll();
    }

    @GetMapping("/person/id/{id}")
    public Person getPersonById(@PathVariable("id") int personId) {
        logger.debug("Get person by id {}", personId);
        return personService.getById(personId);
    }

    @GetMapping("/person/byFirstName")
    public List<Person> getByFirstName(@RequestParam("firstName") String firstName) {
        logger.debug("Get person by first name: {}", firstName);
        return personService.getByFistName(firstName);
    }

    @GetMapping("/person/byFirstAndLastName")
    public List<Person> getByFirstAndLastName(@RequestParam("fn") String firstName, @RequestParam("ln") String lastName) {
        logger.debug("get by first name: {} and last name: {} ", firstName, lastName);
        return personService.getByFirstNameAndLastName(firstName, lastName);
    }

    @GetMapping("/person/byFirstAndLastNameP/{ln}")
    public List<Person> getByFirstAndLastName1(@RequestParam("firstName") String firstName,
                                               @PathVariable("ln") String lastName) {
        logger.debug("get by first name: {} and last name: {} ", firstName, lastName);
        return personService.getByFirstNameAndLastName(firstName, lastName);
    }

    @GetMapping("/person/byDateBetween")
    public List<Person> getByDateBetween(@RequestParam(value = "from",defaultValue = "") String from,
                                         @RequestParam(value = "to", defaultValue = "") String to) {
        logger.debug("from: {}, to: {}", from, to);
        return personService.getByBirthDateBetween(from, to, Utils.DATE_FORMAT);
    }

    @DeleteMapping("/person/delete/{id}")
    public Person removePerson(@PathVariable("id") int personId) {
        Person deletedPerson = personService.remove(personId);
        logger.debug("deleted person {}", deletedPerson);
        return deletedPerson;
    }

    @PostMapping("/persons")
    public Person addPerson(@RequestBody Person person) {
        logger.debug("add person {}", person);
        return personService.add(person);
    }

    @PutMapping("/persons/{id}")
    public Person modifyPerson(@PathVariable("id") int personId, @RequestBody Person person) {
        Person modifiedPerson = personService.modify(personId, person);
        logger.debug("modified person {}", modifiedPerson);
        return modifiedPerson;
    }
}
