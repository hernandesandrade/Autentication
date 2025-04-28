package com.autentication.controllers;

import com.autentication.dto.LoginDTO;
import com.autentication.dto.RegisterDTO;
import com.autentication.exceptions.RecaptchaException;
import com.autentication.exceptions.UserException;
import com.autentication.infra.security.RecaptchaService;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.services.EmailService;
import com.autentication.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.UUID;

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

    @Autowired
    private RecaptchaService recaptchaService;

    @Autowired
    private EmailService emailService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

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
    public String cadastrar(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @Valid RegisterDTO registerDTO,
                            BindingResult result, RedirectAttributes redirectAttributes, HttpServletRequest request, Model model) {
        try {
            if (result.hasErrors()) {
                return "cadastrar";
            }
            User user = null;
            try {
                if (recaptchaService.verify(recaptchaResponse)) {
                    user = userService.getUserByEmail(registerDTO.email());
                    redirectAttributes.addFlashAttribute("erro", "Já existe uma conta criada com esse email");
                    return "redirect:/cadastrar";
                }
            } catch (UserException | RecaptchaException e) {
                redirectAttributes.addFlashAttribute("erro", e.getMessage());
                return "redirect:/cadastrar";
            }
            if (registerDTO.password().equals(registerDTO.confirmPassword())) {
                user = registerDTO.toUser();
                user.setPassword(passwordEncoder.encode(registerDTO.password()));
                user.setAtivo(false);
                user.setTokenConfirmacaoEmail(UUID.randomUUID().toString());
                user.setTokenConfirmacaoEmailExpires(LocalDateTime.now().plusHours(24));
                userService.saveUser(user);
                try {
                    emailService.enviarEmailConfirmacao(user);
                } catch (RuntimeException e) {
                    redirectAttributes.addFlashAttribute("erro", e.getMessage());
                }
                return "redirect:/login";
            } else {
                redirectAttributes.addFlashAttribute("erro", "A senha de confirmação está diferente");
            }
            return "redirect:/cadastrar";
        } catch (Exception e) {
            String referer = request.getHeader("Referer");
            if (referer != null && !referer.isEmpty()) {
                model.addAttribute("voltarUrl", referer);
            }
            model.addAttribute("error", e.getClass().getSimpleName() + "\n" +
                    e.getMessage()+"\n"+
                    e.getStackTrace()[0]);
            return "erro";
        }
    }

    @PostMapping("/login")
    public String logar(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @Valid LoginDTO loginDTO, BindingResult result, HttpServletResponse response, HttpServletRequest request, RedirectAttributes redirectAttributes, Model model) {
        try {
            if (result.hasErrors()) {
                return "login";
            }
            boolean recaptchaMarcado = false;
            if (recaptchaService.isPresent(loginDTO.email())) {
                try {
                    if (recaptchaService.verify(recaptchaResponse)) {
                        recaptchaMarcado = true;
                    } else {
                        redirectAttributes.addFlashAttribute("erro", "Clique em 'Eu não sou um robô'");
                    }
                } catch (RecaptchaException e) {
                    redirectAttributes.addFlashAttribute("recaptchaErros", true);
                    redirectAttributes.addFlashAttribute("erro", e.getMessage());
                }
            }
            if (!recaptchaService.isPresent(loginDTO.email()) || recaptchaMarcado) {
                try {
                    if (userService.getUser(request) != null) {
                        return "redirect:/perfil";
                    }
                    User user = userService.getUserByEmail(loginDTO.email());
                    if (passwordEncoder.matches(loginDTO.password(), user.getPassword())) {

                        String token = tokenService.generateToken(user);
                        Cookie cookie = new Cookie("auth_token", token);
                        cookie.setHttpOnly(true);
                        cookie.setPath("/");
                        response.addCookie(cookie);

                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        if (savedRequest != null) {
                            return "redirect:" + savedRequest.getRedirectUrl();
                        }
                        recaptchaService.loginSucceeded(user.getEmail());
                        return "redirect:/";
                    } else {
                        recaptchaService.loginFailed(user.getEmail());
                        redirectAttributes.addFlashAttribute("erro", "Senha inválida");
                        redirectAttributes.addFlashAttribute("recaptchaErros", recaptchaService.isPresent(user.getEmail()));
                        return "redirect:/login";
                    }
                } catch (AuthenticationException e) {
                    redirectAttributes.addFlashAttribute("erro", "Falha na autenticação: " + e.getMessage());
                } catch (UserException e) {
                    redirectAttributes.addFlashAttribute("erro", e.getMessage());
                }
            }
            return "redirect:/login";
        } catch (Exception e) {
            String referer = request.getHeader("Referer");
            if (referer != null && !referer.isEmpty()) {
                model.addAttribute("voltarUrl", referer);
            }
            model.addAttribute("error", e.getMessage());
            return "erro";
        }
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
    public String login(Authentication authentication, @ModelAttribute("loginDTO") LoginDTO loginDTO) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/perfil";
        }
        return "login";
    }

    @GetMapping("/cadastrar")
    public String cadastro(@ModelAttribute("registerDTO") RegisterDTO registerDTO, Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()) {
            return "redirect:/perfil";
        }
        return "cadastrar";
    }

    @GetMapping("/logout")
    public String logout() {
        return "redirect:/";
    }


}


