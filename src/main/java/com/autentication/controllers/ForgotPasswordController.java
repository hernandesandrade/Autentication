package com.autentication.controllers;

import com.autentication.dto.EmailDTO;
import com.autentication.exceptions.RecaptchaException;
import com.autentication.exceptions.UserException;
import com.autentication.infra.security.RecaptchaService;
import com.autentication.models.User;
import com.autentication.services.PasswordResetService;
import com.autentication.services.UserService;
import com.autentication.validation.EmailValido;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Controller
@RequestMapping("/forgot-password")
public class ForgotPasswordController {

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private UserService userService;

    @Autowired
    private RecaptchaService recaptchaService;

    @GetMapping
    public String showForgotPasswordFrom(@ModelAttribute("emailDTO") EmailDTO emailDTO) {
        return "forgot-password";
    }

    @PostMapping
    public String processForgotPassword(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @Valid EmailDTO emailDTO, BindingResult result, Model model) {
        if (result.hasErrors()) {
            return "forgot-password";
        }
        try {
            recaptchaService.verify(recaptchaResponse);
            User user = userService.getUserByEmail(emailDTO.email());
            String token = UUID.randomUUID().toString();
            passwordResetService.createPasswordResetForUser(user, token);
            passwordResetService.sendEmailResetPassword(user, token);
            model.addAttribute("message", "Link de redefinição de senha enviado para seu email!");
        } catch (RecaptchaException | UserException e) {
            model.addAttribute("erro", e.getMessage());
        }
        return "forgot-password";
    }


}
