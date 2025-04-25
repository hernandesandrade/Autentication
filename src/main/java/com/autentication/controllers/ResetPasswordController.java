package com.autentication.controllers;

import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import com.autentication.services.PasswordResetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/reset-password")
public class ResetPasswordController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping
    public String showResetPasswordFrom(@RequestParam("token") String token, Model model){
        try {
            User user = passwordResetService.validatePasswordResetToken(token);
            model.addAttribute("token", token);
            return "reset-password";
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password-error";
        }
    }

    @PostMapping
    public String processResetPassword(@RequestParam("token") String token, @RequestParam("password") String password, @RequestParam("confirmPassword") String confirmPassword, Model model){
        try {
            if (password.equals(confirmPassword)){
                User user = passwordResetService.validatePasswordResetToken(token);
                user.setPassword(passwordEncoder.encode(password));
                user.setTokenResetPassword(null);
                user.setTokenResetPasswordExpires(null);
                userRepository.save(user);
                return "redirect:/login";
            }else{
                model.addAttribute("erro", "As senhas nao coincidem");
                return "reset-password";
            }
        } catch (RuntimeException e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password-error";
        }

    }


}
