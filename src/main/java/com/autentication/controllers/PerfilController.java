package com.autentication.controllers;

import com.autentication.dto.UserDTO;
import com.autentication.exceptions.UserException;
import com.autentication.models.User;
import com.autentication.services.UserService;
import com.autentication.utils.UserNameFormatter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class PerfilController {

    @Autowired
    private UserService userService;

    @GetMapping("/perfil")
    public String perfil(@ModelAttribute("userDTO") UserDTO userDTO, Model model, HttpServletRequest request) {
        UserDTO user = userService.getUserSession(request);
        if (user != null) {
            userDTO.setName(user.getName());
            userDTO.setEmail(user.getEmail());
            userDTO.setAtivo(user.isAtivo());
            return "perfil";
        } else {
            return "redirect:/logout";
        }
    }

    @PostMapping("/atualizarConta")
    public String atualizarPerfil(@Valid UserDTO userDTO, BindingResult bindingResult, Model model, HttpServletRequest request) {
        if (bindingResult.hasErrors()) {
            return "perfil";
        }
        User user = userService.getUser(request);
        if (user != null) {
            user.setName(UserNameFormatter.formatar(userDTO.getName()));
            userService.atualizarUser(user, request);
            return "redirect:/perfil";
        } else {
            return "redirect:/logout";
        }
    }

}
