package com.autentication.dto;

import com.autentication.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

public record RegisterRequestDTO(String name, String email, String password, String confirmPassword){

    public User toUser(){
        User user = new User();
        user.setName(this.name);
        user.setEmail(this.email);
        return user;
    }

}
