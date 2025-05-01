package com.autentication.dto;

import com.autentication.validation.EmailValido;
import com.autentication.validation.NomeValido;

public class UserDTO {

    @NomeValido
    private String name;
    @EmailValido
    private String email;

    private Boolean ativo;

    public UserDTO(String name, String email, Boolean ativo) {
        this.name = name;
        this.email = email;
        this.ativo = ativo;
    }

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

    public Boolean isAtivo() {
        return ativo;
    }

    public void setAtivo(Boolean ativo) {
        this.ativo = ativo;
    }
}
