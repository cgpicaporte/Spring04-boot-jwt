package com.cgpicaporte.springboot.app.auth.filter;

import java.io.IOException;
//import java.util.Collection;
//import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.cgpicaporte.springboot.app.auth.service.JWTService;
import com.cgpicaporte.springboot.app.auth.service.JWTServiceImpl;
import com.cgpicaporte.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private AuthenticationManager authenticationManager;
	//Añadimos el Service JWTServiceImpl, NO se inyecta en el filtro.
	private JWTService jwtService;
	
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login","POST"));
		
		this.jwtService = jwtService;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		//obtainUsername por clase padre tambien podría usar:
		//String username = request.getParameter("username");
		//String password = request.getParameter("password");
		String username = obtainUsername(request);
		String password = obtainPassword(request);

//Con el añadido del raw ya no tiene sentido estos if
//		if (username == null) {
//			username = "";
//		}
//
//		if (password == null) {
//			password = "";
//		}

		if(username != null && password != null) {
			logger.info("Username desde request parameter (form-data): " + username);
			logger.info("Password desde request parameter (form-data): " + password);
		}else {
			
			Usuario user = null;
			
			try {
				user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
			} catch (JsonParseException e) {
				e.printStackTrace();
			} catch (JsonMappingException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}

			username = user.getUsername();
			password = user.getPassword();
			
			logger.info("Username desde request ImputStream (raw): " + username);
			logger.info("Password desde request ImputStream (raw): " + password);
			
		}
		
		username = username.trim();
		
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		return authenticationManager.authenticate(authToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		/* *****************************
		 * lo llevamos a JWTServiceImpl
		 * *****************************
		String username =((User) authResult.getPrincipal()).getUsername();
		
		//Para obtener los roles
		Collection<? extends GrantedAuthority> roles = authResult.getAuthorities();
		//Los roles se meten a traves de los claims como un dato extra
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));
		
		
		
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.signWith(SignatureAlgorithm.HS512, "Alguna.Clave.Secreta.123456".getBytes())
				.setIssuedAt(new Date())
				//.setExpiration(new Date(System.currentTimeMillis() + 3600000))//1 hora -> para 4 horas sería: 3600000*4 que serían 14000000
				.setExpiration(new Date(System.currentTimeMillis() + 14000000L))// L -> porque es un Long
				.compact();
		*/
		
		//Creamos el token con al llamada la JWTServiceImpl
		String token = jwtService.create(authResult);
		
		response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX + token);
		
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("token", token);
		body.put("user", (User) authResult.getPrincipal());
		//body.put("mensaje", String.format("Hola %s, has iniciado sesión con exito!", username));
		body.put("mensaje", String.format("Hola %s, has iniciado sesión con exito!", ((User) authResult.getPrincipal()).getUsername()));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");

	}

	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("mensaje", "Error de autenticación: username o password incorrectos!");
		body.put("error", failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);
		response.setContentType("application/json");
		
	}
	
}
