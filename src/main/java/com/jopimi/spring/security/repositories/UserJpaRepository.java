package com.jopimi.spring.security.repositories;

import com.jopimi.spring.security.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserJpaRepository extends JpaRepository<User, Integer> {

  boolean existsByUsername(String username);

  Optional<User> findByUsername(String username);
}
