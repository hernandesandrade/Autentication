package com.autentication.controllers;

import com.autentication.exceptions.UserException;
import com.autentication.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
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
    public String confirmarEmail(@RequestParam String token, Model model, HttpServletRequest request) {
        try {
            userService.ativarUsuario(token, request);
            model.addAttribute("mensagem", "Email confirmado com sucesso! Agora você pode fazer login.");
        } catch (UserException e) {
            model.addAttribute("erro", e.getMessage());
        }
        return "confirmacao";
    }

}
