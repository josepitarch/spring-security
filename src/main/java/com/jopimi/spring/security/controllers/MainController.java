package com.jopimi.spring.security.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

  @GetMapping("/hello")
  @PreAuthorize("hasAuthority('ADMIN')")
  public String index() {
    return "Hello World";
  }
}
