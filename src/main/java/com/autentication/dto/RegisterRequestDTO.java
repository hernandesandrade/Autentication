package com.autentication.dto;

import com.autentication.models.User;
import com.autentication.utils.NomeValidator;

public record RegisterRequestDTO(String name, String email, String password, String confirmPassword){

    public User toUser(){
        String nomeAjustado = NomeValidator.formatarNome(this.name);
        User user = new User();
        user.setName(nomeAjustado);
        user.setEmail(this.email);
        return user;
    }

}
