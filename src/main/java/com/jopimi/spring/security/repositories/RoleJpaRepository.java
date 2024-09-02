package com.jopimi.spring.security.repositories;

import com.jopimi.spring.security.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleJpaRepository extends JpaRepository<Role, Integer> {

  Optional<Role> findByName(String name);

}
