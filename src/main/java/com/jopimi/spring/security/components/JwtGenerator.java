package com.jopimi.spring.security.components;

import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtGenerator {

  public long JWT_EXPIRATION = 70000;
  private final SecretKey secretKey = Jwts.SIG.HS256.key().build();

  public String generateToken(Authentication authentication) {
    String username = authentication.getName();
    var currentDate = new Date();
    var expireDate = new Date(currentDate.getTime() + JWT_EXPIRATION);

    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    List<String> roles = authorities.stream().map(GrantedAuthority::getAuthority).toList();

    return Jwts.builder()
            .subject(username)
            .claim("roles", roles)
            .issuedAt(new Date())
            .expiration(expireDate)
            .signWith(secretKey)
            .compact();
  }

  public String getUsernameFromJWT(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getSubject();
  }

  public boolean validateToken(String token) {
    try {
      Jwts.parser().verifyWith(secretKey).build().parse(token);
      return true;
    } catch (Exception ex) {
      throw new AuthenticationCredentialsNotFoundException("JWT was exprired or incorrect", ex.fillInStackTrace());
    }
  }

  public List<String> getRolesFromJWT(String token) {
    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("roles", List.class);
  }

}
