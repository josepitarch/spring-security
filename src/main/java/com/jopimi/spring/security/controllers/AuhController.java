package com.jopimi.spring.security.controllers;

import com.jopimi.spring.security.components.JwtGenerator;
import com.jopimi.spring.security.entities.User;
import com.jopimi.spring.security.repositories.RoleJpaRepository;
import com.jopimi.spring.security.repositories.UserJpaRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuhController {

  private final UserJpaRepository userJpaRepository;

  private final RoleJpaRepository roleJpaRepository;

  private final AuthenticationManager authenticationManager;

  private final PasswordEncoder passwordEncoder;

  private final JwtGenerator jwtGenerator;

  @PostMapping("/login")
  public ResponseEntity login(@RequestBody Map<String, String> loginDto) {
    try {
      Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(loginDto.get("username"), loginDto.get("password")));

      SecurityContextHolder.getContext().setAuthentication(authentication);

      String token = jwtGenerator.generateToken(authentication);

      return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    } catch (AuthenticationException e) {
      return new ResponseEntity<>("Invalid username or password!", HttpStatus.BAD_REQUEST);
    }
  }

  @PostMapping("/register")
  public ResponseEntity register(@RequestBody Map<String, String> registerDto) {
    if (userJpaRepository.existsByUsername(registerDto.get("username"))) {
      return new ResponseEntity<>("Username is taken!", HttpStatus.BAD_REQUEST);
    }

    var appUser = new User();
    appUser.setUsername(registerDto.get("username"));
    appUser.setPassword(passwordEncoder.encode((registerDto.get("password"))));

    var role = roleJpaRepository.findByName(registerDto.get("role").toUpperCase()).get();
    appUser.setRole(role);

    userJpaRepository.save(appUser);

    return new ResponseEntity<>("User registered success!", HttpStatus.OK);
  }

}
