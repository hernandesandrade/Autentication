package com.autentication.dto;

import com.autentication.models.User;
import com.autentication.utils.UserNameFormatter;
import com.autentication.validation.EmailValido;
import com.autentication.validation.NomeValido;
import com.autentication.validation.SenhaValida;
import jakarta.validation.constraints.NotBlank;

public record RegisterDTO(@NomeValido String name, @EmailValido String email, @SenhaValida String password, @NotBlank String confirmPassword){

    public User toUser(){
        String nomeAjustado = UserNameFormatter.formatar(this.name);
        User user = new User();
        user.setName(nomeAjustado);
        user.setEmail(this.email);
        return user;
    }

}
