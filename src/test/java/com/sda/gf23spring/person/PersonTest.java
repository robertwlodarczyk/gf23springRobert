package com.sda.gf23spring.person;

import org.junit.jupiter.api.Test;

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

}