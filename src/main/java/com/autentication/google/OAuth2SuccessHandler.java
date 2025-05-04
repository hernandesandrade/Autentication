package com.autentication.google;

import com.autentication.dto.UserDTO;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        Optional<User> optionalUser = userRepository.findByEmail(email);
        User user;
        System.out.println("buscando conta google...");
        if (optionalUser.isEmpty()) {
            System.out.println("conta criada com google");
            user = new User();
            user.setEmail(email);
            user.setName(name);
            user.setPassword(""); // ou algum marcador indicando que a senha veio do Google
            user.setRole("USER");
            user.setAtivo(true);
            userRepository.save(user);
        } else {
            System.out.println("conta encontrado com google");
            user = optionalUser.get();
        }

        // Criar o token JWT
        String token = tokenService.generateToken(user);

        // Criar cookie do token
        Cookie cookie = new Cookie("auth_token", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        // Adicionar user na sessão
        request.getSession().setAttribute("userLogado", new UserDTO(user.getName(), user.getEmail(), user.isAtivo()));
        // Redirecionar para a página inicial ou a que o usuário tentou acessar

        SavedRequest savedRequest = (SavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");
        if (savedRequest != null) {
            System.out.println("redirecionado para link em cache");
            response.sendRedirect(savedRequest.getRedirectUrl());
        } else {
            response.sendRedirect("/");
        }
    }
}

