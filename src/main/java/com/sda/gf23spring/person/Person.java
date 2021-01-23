package com.sda.gf23spring.person;

import com.sda.gf23spring.utils.Utils;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.time.LocalDate;

public class Person {
    private int personId;
    @NotNull
    @Size(min = 2, message = "Imie powinno posiadać między 2 a 20 znaków")
    private String firstName;
    @NotNull
    @Size(min = 2, message = "Nazwisko powinno posiadać między 2 a 20 znaków")
    private String lastName;
    private LocalDate birthDate;
    @Pattern(regexp = "[\\d]{4}-[\\d]{2}-[\\d]{2}", message = "Nieprawidłowa data")
    private String birthDateS;
    private double salary;

    public Person() {
    }

    public Person(String firstName, String lastName, LocalDate birthDate, double salary) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.birthDate = birthDate;
        this.salary = salary;
    }

    public int getPersonId() {
        return personId;
    }

    public void setPersonId(int personId) {
        this.personId = personId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public LocalDate getBirthDate() {
        return birthDate;
    }

    public void setBirthDate(LocalDate birthDate) {
        this.birthDate = birthDate;
    }

    public double getSalary() {
        return salary;
    }

    public void setSalary(double salary) {
        this.salary = salary;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getBirthDateS() {
        birthDateS=birthDate.format(Utils.DATE_FORMAT_HTML);
        return birthDateS;
    }

    public void setBirthDateS(String birthDateS) {
        birthDate = LocalDate.parse(birthDateS, Utils.DATE_FORMAT_HTML);
        this.birthDateS = birthDateS;
    }

    @Override
    public String toString() {
        return "Person{" +
                "personId=" + personId +
                ", firstName='" + firstName + '\'' +
                ", lastName='" + lastName + '\'' +
                ", birthDate=" + birthDate +
                ", salary=" + salary +
                '}';
    }
}
