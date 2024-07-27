package dio.spring.security.jwt.controller;

import dio.spring.security.jwt.dtos.Login;
import dio.spring.security.jwt.dtos.Sessao;
import dio.spring.security.jwt.model.User;
import dio.spring.security.jwt.repository.UserRepository;
import dio.spring.security.jwt.security.JWTCreator;
import dio.spring.security.jwt.security.JWTObject;
import dio.spring.security.jwt.security.SecurityConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

@RestController
public class LoginController {
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private SecurityConfig securityConfig;
    @Autowired
    private UserRepository repository;

    @PostMapping("/login")
    public Sessao logar(@RequestBody Login login) {
        logger.info("Tentativa de login com username: {}", login.getUsername());
        User user = repository.findByUsername(login.getUsername());
        if (user != null) {
            boolean passwordOk = encoder.matches(login.getPassword(), user.getPassword());
            if (!passwordOk) {
                logger.warn("Senha inválida para o login: {}", login.getUsername());
                throw new RuntimeException("Senha inválida para o login: " + login.getUsername());
            }
            //Estamos enviando um objeto Sessão para retornar mais informações do usuário
            Sessao sessao = new Sessao();
            sessao.setLogin(user.getUsername());

            JWTObject jwtObject = new JWTObject();
            jwtObject.setIssuedAt(new Date(System.currentTimeMillis()));
            jwtObject.setExpiration((new Date(System.currentTimeMillis() + SecurityConfig.EXPIRATION)));
            jwtObject.setRoles(user.getRoles());
            sessao.setToken(JWTCreator.create(SecurityConfig.PREFIX, SecurityConfig.KEY, jwtObject));

            logger.info("Login bem-sucedido para username: {}", login.getUsername());
            return sessao;
        } else {
            logger.error("Erro ao tentar fazer login: usuário {} não encontrado", login.getUsername());
            throw new RuntimeException("Erro ao tentar fazer login");
        }
    }
}
