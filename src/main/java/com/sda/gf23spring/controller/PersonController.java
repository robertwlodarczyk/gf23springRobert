package com.sda.gf23spring.controller;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.service.PersonService;
import com.sda.gf23spring.utils.Utils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

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
        model.addAttribute("person", new Person());
        return "addPerson";
    }

    @PostMapping("/spersons")
    public String savePerson(@Valid Person person, BindingResult result) {
        if (result.hasErrors()) {
            result.getAllErrors().forEach(xx -> System.out.println(xx.getDefaultMessage()));
            return "addPerson";
        }
        personService.add(person);
        return "redirect:/spersons";
    }

    @GetMapping("/delPerson")
    public String delPerson(@RequestParam("id") int personId) {
        personService.remove(personId);
        return "redirect:/spersons";
    }

    @GetMapping("/modifyPerson/{id}")
    public String modifyPerson(@PathVariable("id") int personIdModify, Model modelModify) {
        Person byId = personService.getById(personIdModify);
        modelModify.addAttribute("person", byId);
        return "modifyPerson";
    }

    @PostMapping("/spersonsM")
    public String savePersonM(@Valid Person person, BindingResult result) {
        if (result.hasErrors()) {
            result.getAllErrors().forEach(xx -> System.out.println(xx.getDefaultMessage()));
            return "modifyPerson";
        }
        System.out.println(person);
        personService.modify(person.getPersonId(), person);
        return "redirect:/spersons";
    }

    @GetMapping("/sPersonsByAge")
    public String sPersonsByAge(@RequestParam("min") String min, @RequestParam("max") String max, Model model) {
        List<Person> personList = personService.getByBirthDateBetween(min,max, Utils.DATE_FORMAT_HTML);
        model.addAttribute("persons",personList);
        return "selectedPersons";
    }


}
