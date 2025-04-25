package com.autentication.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ResetPasswordErrorController {

    @GetMapping("/reset-password-error")
    public String a(){
        return "reset-password-error";
    }
}
