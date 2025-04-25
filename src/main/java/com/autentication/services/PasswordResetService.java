package com.autentication.services;

import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class PasswordResetService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    @Value("${app.url}")
    private String baseUrl;

    public void createPasswordResetForUser(User user, String token){
        user.setTokenResetPassword(token);
        user.setTokenResetPasswordExpires(LocalDateTime.now().plusHours(24));
        userRepository.save(user);
    }

    public void sendEmailResetPassword(User user, String token){
        String url = baseUrl + "/reset-password?token=" + token;

        SimpleMailMessage email = new SimpleMailMessage();
        email.setFrom(fromEmail);
        email.setTo(user.getEmail());
        email.setSubject("Redefinição de senha");
        email.setText(
                "Para redefinir sua senha, clique no link abaixo: \n" +
                url + "\n\n" +
                "Se você não solicitou essa redefinição, ignore este email.");
        javaMailSender.send(email);
    }

    public User validatePasswordResetToken(String token){
        User user = userRepository.findByTokenResetPassword(token).orElseThrow(
                () -> new RuntimeException("Token inválido"));
        if (user.getTokenResetPasswordExpires().isBefore(LocalDateTime.now())){
            throw new RuntimeException("Token expirado");
        }
        return user;
    }


}
