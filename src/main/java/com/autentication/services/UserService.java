package com.autentication.services;

import com.autentication.dto.RegisterDTO;
import com.autentication.dto.UserDTO;
import com.autentication.exceptions.EmailException;
import com.autentication.exceptions.UserException;
import com.autentication.infra.security.SecurityFilter;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private EmailService emailService;

    @Autowired
    private SecurityFilter securityFilter;

    @Autowired
    private TokenService tokenService;

    public UserDTO getUserSession(HttpServletRequest request) {
        Object ob = request.getSession().getAttribute("userLogado");
        return (UserDTO) ob;
    }

    public User getUser(HttpServletRequest request) {
        String token = securityFilter.extractTokenFromCookies(request);
        if (token != null) {
            String email = tokenService.validateToken(token);
            if (email != null) {
                return userRepository.findByEmail(email).orElse(null);
            }
        }
        return null;
    }

    public User getUserById(String id) throws UserException {
        Optional<User> user = userRepository.findById(id);
        return user.orElseThrow(() -> new UserException("Não existe um usuário com esse id")); // Retorna o usuário ou null se não existir
    }

    public User getUserByEmail(String email) throws UserException {
        Optional<User> user = userRepository.findByEmail(email);
        return user.orElseThrow(() -> new UserException("Não existe um usuário com esse email"));
    }

    public User getUserByEmail(String email, boolean erro) throws UserException {
        if (erro) {
            return getUserByEmail(email);
        }else{
            return userRepository.findByEmail(email).orElse(null);
        }
    }

    public void cadastrarUser(RegisterDTO registerDTO) throws EmailException {
        User user = new User();
        user = registerDTO.toUser();
        user.setPassword(passwordEncoder.encode(registerDTO.password()));
        user.setAtivo(false);
        user.setTokenConfirmacaoEmail(UUID.randomUUID().toString());
        user.setTokenConfirmacaoEmailExpires(LocalDateTime.now().plusHours(24));
        saveUser(user);
        emailService.enviarEmailConfirmacao(user);
    }

    public void saveUser(User user){
        userRepository.save(user);
    }

    public void atualizarUser(User user, HttpServletRequest request){
        userRepository.save(user);
        request.getSession().setAttribute("userLogado", new UserDTO(user.getName(), user.getEmail(), user.isAtivo()));
    }

    public void ativarUsuario(String token) throws UserException {
        User usuario = userRepository.findByTokenConfirmacaoEmail(token)
                .orElseThrow(() -> new UserException("Token inválido"));

        if (usuario.getTokenConfirmacaoEmailExpires().isBefore(LocalDateTime.now())) {
            throw new UserException("Token expirado");
        }

        usuario.setAtivo(true);
        usuario.setTokenConfirmacaoEmail(null);
        userRepository.save(usuario);
    }
}
