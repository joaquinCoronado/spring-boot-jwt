package io.posdata.springsecuritymito.config.auth;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.security.Keys;
import lombok.extern.java.Log;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.Key;
import java.util.Collection;

import io.jsonwebtoken.Jwts;

public @Log class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader("Authorization");

        if(!requiresAuthentication(header)){
            chain.doFilter(request, response);
            return;
        }

        boolean validToken = false;
        Claims claims = null;
        Key key = Keys.hmacShaKeyFor("clave.super.segura.para.la.autenticacion.de.mi.servicio.web.con.api.res".getBytes());

        try {
            claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(header.replace("Bearer ", ""))
                    .getBody();
            validToken = true;
        } catch(Exception e){
            log.info("Error: " + e.getMessage());
        }

        if(validToken){
            String  userName = claims.getSubject();

            Type typeToken = new TypeToken<Collection<SimpleGrantedAuthority>>(){}.getType();

            Collection<? extends GrantedAuthority> roles = new Gson().fromJson(
                    claims.get("authorities").toString(),
                    typeToken
            );

            log.info("roles: " + new Gson().toJson(roles));

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userName, null, roles);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        }

    }

    protected boolean requiresAuthentication(String header){
        if(header == null || !header.startsWith("Bearer ")){
            return false;
        }
        return true;
    }
}

