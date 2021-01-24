package com.sda.gf23spring.person;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class PersonTest {
    @Test
    void getBirthDateS(){

    }

    @Test
    void setBirthDateS(){
        Person p = new Person();
        p.setBirthDateS(null);
        System.out.println(p.getBirthDateS());
        System.out.println(p.getBirthDate());
    }

    @Test
    void password(){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        System.out.println(encoder.encode("Robert"));
        System.out.println(encoder.encode("ania"));
    }
}