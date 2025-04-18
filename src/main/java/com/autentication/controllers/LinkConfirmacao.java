package com.autentication.controllers;

import com.autentication.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LinkConfirmacao {

    @Autowired
    private UserService userService;

    @GetMapping("/confirmar-email")
    public String confirmarEmail(@RequestParam String token, Model model) {
        try {
            userService.ativarUsuario(token);
            model.addAttribute("mensagem", "Email confirmado com sucesso! Agora você pode fazer login.");
        } catch (RuntimeException e) {
            model.addAttribute("erro", e.getMessage());
        }
        return "confirmacao";
    }

}
