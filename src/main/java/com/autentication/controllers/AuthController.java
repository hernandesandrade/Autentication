package com.autentication.controllers;

import com.autentication.dto.LoginDTO;
import com.autentication.dto.RegisterDTO;
import com.autentication.dto.UserDTO;
import com.autentication.exceptions.EmailException;
import com.autentication.exceptions.UserException;
import com.autentication.infra.security.RecaptchaService;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.services.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private HttpSessionRequestCache requestCache;

    @Autowired
    private RecaptchaService recaptchaService;

    @PostMapping("/cadastrar")
    public String cadastrar(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @Valid RegisterDTO registerDTO,
                            BindingResult result, HttpServletRequest request, Model model) {
        try {
            if (result.hasErrors()) {
                recaptchaService.loginFailed(request, registerDTO.email());
                model.addAttribute("recaptchaErros", recaptchaService.isPresent(request, registerDTO.email()));
                return "cadastrar";
            }
            if (userService.getUserByEmail(registerDTO.email(), false) == null) {
                if (registerDTO.password().equals(registerDTO.confirmPassword())) {
                    recaptchaService.verify(recaptchaResponse);
                    userService.cadastrarUser(registerDTO);
                    return "redirect:/login";
                } else {
                    enviarErro("A senha de confirmação está diferente", "confirmPassword", result, model);
                }
            } else {
                enviarErro("Já existe uma conta criada com esse email", "email", result, model);
            }
        } catch (UserException | EmailException e) {
            enviarErro(e.getMessage(), "email", result, model);
        } catch (Exception e) {
            model.addAttribute("erroGlobal", e.getMessage());
        }
        return "cadastrar";
    }

    @PostMapping("/login")
    public String logar(@RequestParam(name = "g-recaptcha-response", required = false) String recaptchaResponse, @Valid LoginDTO loginDTO, BindingResult result,
                        HttpServletResponse response, HttpServletRequest request, Model model) {
        try {
            if (result.hasErrors()) {
                recaptchaService.loginFailed(request, loginDTO.email());
                model.addAttribute("recaptchaErros", recaptchaService.isPresent(request, loginDTO.email()));
                return "login";
            }
            if (recaptchaService.isPresent(request, loginDTO.email())) {
                recaptchaService.verify(recaptchaResponse);
            }
            if (userService.getUserSession(request) == null) {
                User user = userService.getUserByEmail(loginDTO.email());
                if (passwordEncoder.matches(loginDTO.password(), user.getPassword())) {
                    request.getSession().setAttribute("userLogado", new UserDTO(user.getName(), user.getEmail(), user.isAtivo()));
                    String token = tokenService.generateToken(user);
                    Cookie cookie = new Cookie("auth_token", token);
                    cookie.setHttpOnly(true);
                    cookie.setPath("/");
                    response.addCookie(cookie);
                    SavedRequest savedRequest = requestCache.getRequest(request, response);
                    recaptchaService.loginSucceeded(request, user.getEmail());
                    if (savedRequest != null) {
                        return "redirect:" + savedRequest.getRedirectUrl();
                    }
                    return "redirect:/";
                } else {
                    enviarErro("Senha inválida", "password", result, model);
                }
            } else {
                return "redirect:/perfil";
            }
        } catch (UserException e) {
            enviarErro(e.getMessage(), "email", result, model);
        } catch (Exception e) {
            model.addAttribute("erroGlobal", e.getMessage());
        }
        recaptchaService.loginFailed(request, loginDTO.email());
        model.addAttribute("recaptchaErros", recaptchaService.isPresent(request, loginDTO.email()));
        return "login";
    }

    private void enviarErro(String mensagem, String campo, BindingResult result, Model model) {
        result.rejectValue(campo, "erro." + campo, mensagem);
        model.addAttribute("campoErro", campo);
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
    public String logout(HttpServletRequest request) {
        return "redirect:/";
    }

/*
    @GetMapping("/debug-roles")
    @ResponseBody
    public String debugRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return "Usuário autenticado: " + authentication.getName() + "<br>Authorities: " + authorities;
    }
*/

}


