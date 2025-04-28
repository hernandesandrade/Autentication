package com.autentication.services;

import com.autentication.exceptions.UserException;
import com.autentication.infra.security.SecurityFilter;
import com.autentication.infra.security.TokenService;
import com.autentication.models.User;
import com.autentication.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TokenService tokenService;

    @Autowired
    private SecurityFilter securityFilter;

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

    public void saveUser(User user){
        userRepository.save(user);
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
