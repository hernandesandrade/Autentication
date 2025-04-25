package com.autentication.controllers;

import com.autentication.infra.security.RecaptchaService;
import com.autentication.models.User;
import com.autentication.services.PasswordResetService;
import com.autentication.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

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
    public String showForgotPasswordFrom() {
        return "forgot-password";
    }

    @PostMapping
    public String processForgotPassword(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @RequestParam("email") String email, Model model) {
        try {
            if (recaptchaService.verify(recaptchaResponse)){
                User user = userService.getUserByEmail(email);
                String token = UUID.randomUUID().toString();
                passwordResetService.createPasswordResetForUser(user, token);
                passwordResetService.sendEmailResetPassword(user, token);
                model.addAttribute("message", "Se o email existir em nosso sistema, enviaremos uim link de redefinição");
            }else{
                model.addAttribute("erro", "Marque a caixa 'Eu não sou um robÔ'");
            }
        } catch (Exception e) {
            model.addAttribute("erro", e.getMessage());
        }
        return "forgot-password";
    }


}
