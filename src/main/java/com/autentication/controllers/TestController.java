package com.autentication.controllers;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class TestController {

    @GetMapping("/form")
    public String showForm() {
        return "form";
    }

    @PostMapping("/transfer")
    public String transfer(@RequestParam int amount, Model model, CsrfToken token) {
        if (token != null) {
            System.out.println("CSRF Token: " + token.getToken()); // Debug
        }
        System.out.println("Transferência de R$" + amount + " realizada!");
        return "form";
    }
}
