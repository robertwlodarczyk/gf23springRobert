package com.sda.gf23spring;

import com.sda.gf23spring.person.Person;
import com.sda.gf23spring.repository.PersonDao;
import com.sda.gf23spring.repository.PersonDaoHibernate;
import com.sda.gf23spring.service.PersonService;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ProgStarter implements CommandLineRunner {
    Logger logger;
    MessageSource messageSource;

    PersonService personService;
    PersonDao personDao;
    PersonDaoHibernate personDaoHibernate;

    @Override
    public void run(String... args) throws Exception {
        List<Person> all = personDao.getAll();
        personDaoHibernate.saveAll(all);

    }

    @Autowired
    public void setPersonDao(PersonDao personDao) {
        this.personDao = personDao;
    }

    @Autowired
    public void setPersonDaoHibernate(PersonDaoHibernate personDaoHibernate) {
        this.personDaoHibernate = personDaoHibernate;
    }

    @Autowired
    public void setMessageSource(MessageSource messageSource) {
        this.messageSource = messageSource;
    }

    @Autowired
    public void setLogger(Logger logger) {
        this.logger = logger;
    }

    @Autowired
    public void setPersonService(PersonService personService) {
        this.personService = personService;
    }
}
