package com.sda.gf23spring.repository;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.utils.Utils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
@Profile("dev")
public class PersonDaoCsvImpl implements PersonDao {
    Map<Integer, Person> personMap = new HashMap<>();

    @Value("${persons.size}")
    private int personsSize;

    @PostConstruct
    public void initPersonMap() throws IOException {
        Files
                .lines(Path.of("persons.csv"))
                .map(x -> x.split(","))
                .map(x -> new Person(x[0], x[1], LocalDate.parse(x[2], Utils.DATE_FORMAT), Double.parseDouble(x[3])))
                .limit(personsSize)
                .forEach(this::add);
    }

    @Override
    public List<Person> getAll() {

        return new ArrayList<>(personMap.values());
    }

    @Override
    public Person getById(int personId) {
        return personMap.get(personId);
    }

    @Override
    public List<Person> getByFistName(String firstName) {
//        if(firstName == null || "".equals(firstName)) {
//            return new ArrayList<>();
//        }
//        return getAll()
//                .stream()
//                .filter(x -> x.getFirstName().toLowerCase().contains(firstName.toLowerCase()))
//                .collect(Collectors.toList());
        return null;
    }

    @Override
    public List<Person> getByLastName(String lastName) {
        if(lastName == null || "".equals(lastName)) {
            return new ArrayList<>();
        }
        return getAll()
                .stream()
                .filter(x -> x.getLastName().toLowerCase().contains(lastName.toLowerCase()))
                .collect(Collectors.toList());
    }

    @Override
    public List<Person> getByBirthDateBetween(LocalDate from, LocalDate to) {
        return getAll()
                .stream()
                .filter(x -> x.getBirthDate().isAfter(from))
                .filter(x -> x.getBirthDate().isBefore(to))
                .collect(Collectors.toList());
    }

    @Override
    public List<Person> getBySalaryBetween(double from, double to) {
        return getAll()
                .stream()
                .filter(x -> x.getSalary() >= from)
                .filter(x -> x.getSalary() <= to)
                .collect(Collectors.toList());
    }

    @Override
    public Person add(Person person) {
        int personId = generatePersonId();
        person.setPersonId(personId);
        personMap.put(person.getPersonId(), person);
        return person;
    }

    private int generatePersonId() {
        int maxId = personMap
                .keySet()
                .stream()
                .mapToInt(x -> x)
                .max()
                .orElse(0);
        return maxId + 1;
    }

    @Override
    public Person modify(int personId, Person person) {
        person.setPersonId(personId);
        personMap.put(personId, person);
        return person;
    }

    @Override
    public Person remove(int personId) {
        return personMap.remove(personId);
    }
}
