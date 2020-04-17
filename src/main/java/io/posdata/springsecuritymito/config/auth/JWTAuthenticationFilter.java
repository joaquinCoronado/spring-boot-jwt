package io.posdata.springsecuritymito.config.auth;

import com.google.gson.Gson;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@AllArgsConstructor
public @Log class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = this.obtainUsername(request);
        String password = this.obtainPassword(request);

        if(username == null || password == null){
            try {
                String body = request.getReader().lines().reduce("", String::concat);
                User user =  new Gson().fromJson(body, User.class);
                username = user.getUsername() != null ? user.getUsername() : "";
                password = user.getPassword()  != null ? user.getPassword() : "";
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        log.info("usuario: " + username + " contraseña:  " + password);

        username = username.trim();
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
        log.info("token: " +  new Gson().toJson(authToken));
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("success");
        String  userName = ((User) authResult.getPrincipal()).getUsername();

        Key key = Keys.hmacShaKeyFor("clave.super.segura.para.la.autenticacion.de.mi.servicio.web.con.api.res".getBytes());

        Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();

        Claims claims = Jwts.claims();
        claims.put("authorities", new Gson().toJson(roles));

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .signWith(key,SignatureAlgorithm.HS512)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000 * 5))
                .compact();

        response.addHeader("Authorization", "Bearer " + token);

        Map<String, String> body = new HashMap<>();
        body.put("token", token);

        response.getWriter().write(new  Gson().toJson(body));
        response.setStatus(200);
        response.setContentType("application/json");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        Map<String, String> body = new HashMap<>();
        body.put("error", failed.getMessage());

        response.getWriter().write(new  Gson().toJson(body));
        response.setStatus(401);
        response.setContentType("application/json");
    }
}
