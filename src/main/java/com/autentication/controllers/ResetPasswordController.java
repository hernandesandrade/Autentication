package com.autentication.controllers;

import com.autentication.dto.PasswordDTO;
import com.autentication.dto.RegisterDTO;
import com.autentication.exceptions.PasswordException;
import com.autentication.models.User;
import com.autentication.services.PasswordResetService;
import com.autentication.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/reset-password")
public class ResetPasswordController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping
    public String showResetPasswordFrom(@RequestParam("token") String token, @ModelAttribute("passwordDTO") RegisterDTO passwordDTO, Model model){
        try {
            User user = passwordResetService.validatePasswordResetToken(token);
            model.addAttribute("token", token);
            return "reset-password";
        } catch (PasswordException e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password-error";
        }
    }

    @PostMapping
    public String processResetPassword(@RequestParam("token") String token, @Valid PasswordDTO passwordDTO, BindingResult result, Model model){
        if (result.hasErrors()) {
            model.addAttribute("token", token);
            return "reset-password";
        }
        try {
            if (passwordDTO.password().equals(passwordDTO.confirmPassword())){
                User user = passwordResetService.validatePasswordResetToken(token);
                user.setPassword(passwordEncoder.encode(passwordDTO.password()));
                user.setTokenResetPassword(null);
                user.setTokenResetPasswordExpires(null);
                userService.saveUser(user);
                return "redirect:/login";
            }else{
                model.addAttribute("erro", "A senha de confirmação está diferente");
                model.addAttribute("token", token);
                return "reset-password";
            }
        } catch (PasswordException e) {
            model.addAttribute("error", e.getMessage());
            return "reset-password-error";
        }

    }


}
