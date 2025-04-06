package com.autentication.controllers;

import com.autentication.dto.LoginRequestDTO;
import com.autentication.dto.RegisterRequestDTO;
import com.autentication.infra.security.LoginAttemptService;
import com.autentication.infra.security.RecaptchaService;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.services.UserService;
import com.autentication.utils.EmailValidator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.nio.file.AccessDeniedException;
import java.util.Collection;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;
    //
    @Autowired
    private TokenService tokenService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private HttpSessionRequestCache requestCache;

    @GetMapping("/debug-roles")
    @ResponseBody
    public String debugRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        System.out.println("Usuário autenticado: " + authentication.getName());
        System.out.println("Authorities: " + authorities);

        return "Usuário autenticado: " + authentication.getName() + "<br>Authorities: " + authorities;
    }

    @PostMapping("/cadastrar")
    public String cadastrar(RegisterRequestDTO registerRequestDTO) {
        User user = null;
        try {
            user = userService.getUserByEmail(registerRequestDTO.email());
            System.out.println("Ja existe uma conta com esse email");
        } catch (RuntimeException e) {
            if (EmailValidator.isValidEmail(registerRequestDTO.email())) {
                if (registerRequestDTO.password().length() >= 5) {
                    if (registerRequestDTO.password().equals(registerRequestDTO.confirmPassword())) {
                        user = registerRequestDTO.toUser();
                        user.setPassword(passwordEncoder.encode(registerRequestDTO.password()));
                        userService.saveUser(user);
                    } else {
                        System.out.println("As senhas nao batem");
                    }
                } else {
                    System.out.println("Senha curta");
                }
            } else {
                System.out.println("Email invalido");
            }
        }
        return "redirect:/cadastrar";
    }

    @Autowired
    private RecaptchaService recaptchaService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @PostMapping("/login")
    public String logar(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, LoginRequestDTO loginRequestDTO, HttpServletResponse response,
                        HttpServletRequest request, Model model) {

        if (userService.getUser(request) != null) {
            System.out.println("voce ja se encontra logado");
            return "redirect:/";
        }
        boolean isValidCaptcha = false;
        if (loginAttemptService.getAttempts(loginRequestDTO.email()) >= 3) {
            try {
                isValidCaptcha = recaptchaService.verify(recaptchaResponse);
            } catch (AccessDeniedException e) {
                System.out.println(e.getMessage());
            }
        }else{
            isValidCaptcha = true;
        }
        if (isValidCaptcha) {
            try {
                User user = userService.getUserByEmail(loginRequestDTO.email());
                if (passwordEncoder.matches(loginRequestDTO.password(), user.getPassword())) {
                    // Gera e adiciona o token como cookie
                    String token = tokenService.generateToken(user);
                    Cookie cookie = new Cookie("auth_token", token);
                    cookie.setHttpOnly(true);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                    // Recupera a URL original armazenada no RequestCache
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    if (savedRequest != null) {
                        String redirectUrl = savedRequest.getRedirectUrl();
                        return "redirect:" + redirectUrl;
                    }
                    loginAttemptService.loginSucceeded(user.getEmail());
                    // Redireciona para a página inicial limpa, caso não exista uma URL salva
                    return "redirect:/";
                }else{
                    loginAttemptService.loginFailed(user.getEmail());
                    model.addAttribute("recaptchaErros", loginAttemptService.getAttempts(user.getEmail()));
                    System.out.println("senha invalida");
                    System.out.println("erros: " + loginAttemptService.getAttempts(user.getEmail()));
                    return "/login";
                }
            } catch (AuthenticationException e) {
                System.out.println("Falha na autenticação: " + e.getMessage());
            }
        }else{
            model.addAttribute("recaptchaErros", loginAttemptService.getAttempts(loginRequestDTO.email()));
            return "/login";
        }
        return "redirect:/login";
    }

    @GetMapping
    public String inicio() {
        return "inicio";
    }

    @GetMapping("/publico")
    public String publico() {
        return "publico";
    }

    @GetMapping("/privado")
    public String paginaPrivada() {
        return "privado1";
    }

    @GetMapping("/privado2")
    public String privado2() {
        return "privado2";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/cadastrar")
    public String cadastro() {
        return "cadastrar";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:";
    }


}


