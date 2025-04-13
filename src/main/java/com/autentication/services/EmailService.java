package com.autentication.services;

import com.autentication.models.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String remetente;

    @Value("${app.url}")
    private String appUrl;

    public void enviarEmailConfirmacao(User usuario) {
        String assunto = "Confirme seu cadastro";
        String token = usuario.getTokenConfirmacao();
        String urlConfirmacao = appUrl + "/confirmar-email?token=" + token;

        String mensagem = "<p>Olá " + usuario.getName() + ",</p>"
                + "<p>Por favor, clique no link abaixo para confirmar seu email:</p>"
                + "<p><a href=\"" + urlConfirmacao + "\">Confirmar Email</a></p>"
                + "<p>O link expirará em 24 horas.</p>";

        MimeMessage email = mailSender.createMimeMessage();

        try {
            MimeMessageHelper helper = new MimeMessageHelper(email, true);
            helper.setFrom(remetente);
            helper.setTo(usuario.getEmail());
            helper.setSubject(assunto);
            helper.setText(mensagem, true);

            mailSender.send(email);
        } catch (MessagingException e) {
            throw new RuntimeException("Falha ao enviar email de confirmação", e);
        }
    }

    // Método similar para recuperação de senha
}
