
package com.sda.gf23spring.person;

import java.io.Serializable;

public class UserRoleId implements Serializable {
    private String login;
    private String role;


    public void setLogin(String login) {
        this.login = login;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getLogin() {
        return login;
    }

    public String getRole() {
        return role;
    }
}