package com.cgpicaporte.springboot.app.auth.filter;

import java.io.IOException;
//import java.util.Arrays;
//import java.util.Collection;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

//import com.cgpicaporte.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.cgpicaporte.springboot.app.auth.service.JWTService;
import com.cgpicaporte.springboot.app.auth.service.JWTServiceImpl;

//import com.fasterxml.jackson.databind.ObjectMapper;

//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.JwtException;
//import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	
	private JWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		String header = request.getHeader(JWTServiceImpl.HEADER_STRING);

		if (!requiresAuthentication(header)) {
			chain.doFilter(request, response);
			return;
		}
		
		/* 
		 * *************************************
		 * lo pasamos a JWTService al validate
		 * *************************************
		boolean tokenValido;
		Claims token = null;
		try {
		token = Jwts.parser()
			.setSigningKey("Alguna.Clave.Secreta.123456".getBytes())
			.parseClaimsJws(header.replace("Bearer ", ""))// quitamos el "Bearer "
			.getBody();
			tokenValido = true;
		}catch (JwtException | IllegalArgumentException e) {
			tokenValido = false;
		}
		*/
		
		UsernamePasswordAuthenticationToken authentication = null;

		/*
		if (tokenValido) {
			String username = token.getSubject();
			Object roles = token.get("authorities");
			
			Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
					.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
					.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
			
			authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
						
		}else {
			
		}
		*/
		
		//Y con el jwtServie hacemos:
		if (jwtService.validate(header)) {
			
			String username = jwtService.getUsername(header);
			Collection<? extends GrantedAuthority> authorities = jwtService.getRoles(header);
			
			authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
			
		}else {
			
		}
		
		
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
				
	}
	
	protected boolean requiresAuthentication(String header) {
	
		if (header == null || !header.startsWith(JWTServiceImpl.TOKEN_PREFIX)) {
			return false;
		}
		return true;
	}

	
	
}
