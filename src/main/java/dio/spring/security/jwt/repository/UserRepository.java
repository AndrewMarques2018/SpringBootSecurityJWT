package dio.spring.security.jwt.repository;

import dio.spring.security.jwt.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public interface UserRepository extends JpaRepository<User, Integer> {
    Logger logger = LoggerFactory.getLogger(UserRepository.class);

    User findByUsername(@Param("username") String username);

    boolean existsByUsername(String username);
}
