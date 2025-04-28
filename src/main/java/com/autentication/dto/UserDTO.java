package com.autentication.dto;

import com.autentication.validation.EmailValido;
import com.autentication.validation.NomeValido;

public class UserDTO {

    @NomeValido
    private String name;
    @EmailValido
    private String email;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
