package com.sda.gf23spring.controller;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.service.PersonService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import javax.validation.Valid;
import java.util.List;


@Controller
public class PersonController {

    private PersonService personService;

    public PersonController(PersonService personService) {
        this.personService = personService;
    }

    @GetMapping("/spersons")
    public String getAllPersons(Model model) {
        List<Person> people = personService.getAll();
        model.addAttribute("persons", people);
        return "index";
    }

    @GetMapping("/sperson/id/{id}")
    public String getPersonById(@PathVariable("id") int personId, Model model) {
        Person byId = personService.getById(personId);
        model.addAttribute("person", byId);
        return "person";
    }

    @GetMapping("/addPerson")
    public String addPerson(Model model) {
        model.addAttribute("newPerson", new Person());
        return "addPerson";
    }

    @PostMapping("/spersons")
    public String savePerson(@Valid Person person, BindingResult result) {
        if(result.hasErrors()) {
            result.getAllErrors().forEach(xx -> System.out.println(xx.getDefaultMessage()));
            return "addPerson";
        }
        personService.add(person);
        return "redirect:/spersons";
    }

}
