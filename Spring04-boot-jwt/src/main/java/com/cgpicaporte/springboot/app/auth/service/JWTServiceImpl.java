package com.cgpicaporte.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.cgpicaporte.springboot.app.auth.SimpleGrantedAuthorityMixin;
//import com.fasterxml.jackson.core.JsonParseException;
//import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

@Component
public class JWTServiceImpl implements JWTService {

	public static String SECRET = Base64Utils.encodeToString("Alguna.Clave.Secreta.123456".getBytes());
	public static long EXPIRATION_DATE = 14000000L;
	public static String TOKEN_PREFIX = "Bearer ";
	public static String HEADER_STRING = "Authorization";
	
	@Override
	//public String create(Authentication auth) throws JsonProcessingException {
	public String create(Authentication auth) throws IOException {

		String username = ((User) auth.getPrincipal()).getUsername();

		// Para obtener los roles
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		// Los roles se meten a traves de los claims como un dato extra
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

		String token = Jwts.builder().setClaims(claims).setSubject(username)
				.signWith(SignatureAlgorithm.HS512, SECRET.getBytes()).setIssuedAt(new Date())
				// .setExpiration(new Date(System.currentTimeMillis() + 3600000))//1 hora ->
				// para 4 horas sería: 3600000*4 que serían 14000000
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))// L -> porque es un Long
				.compact();

		return token;
	}

	@Override
	public boolean validate(String token) {

		/*
		 * //Claims token = null; Claims claims = null; try { //token = Jwts.parser()
		 * claims =
		 * Jwts.parser().setSigningKey("Alguna.Clave.Secreta.123456".getBytes()) //
		 * .parseClaimsJws(header.replace("Bearer ", ""))// quitamos el "Bearer "
		 * .parseClaimsJws(token.replace("Bearer ", ""))// quitamos el "Bearer "
		 * .getBody();
		 * 
		 * return true; }catch (JwtException | IllegalArgumentException e) { return
		 * false; }
		 */

		try {
			getClaims(token);
			return true;
		} catch (JwtException | IllegalArgumentException e) {
			return false;
		}

	}

	@Override
	public Claims getClaims(String token) {

		Claims claims = Jwts.parser().setSigningKey(SECRET.getBytes())
				//.parseClaimsJws(token.replace("Bearer ", ""))// quitamos el "Bearer "
				.parseClaimsJws(resolve(token))// quitamos el "Bearer "
				.getBody();

		return claims;
	}

	@Override
	public String getUsername(String token) {
		//Reutilizamos el getClaims(String token)
		return getClaims(token).getSubject();
	}

	@Override
	//public Collection<? extends GrantedAuthority> getRoles(String token) throws JsonParseException, JsonMappingException, IOException {
	//Nos basta con IOException ya que incluye JsonParseException, JsonMappingException
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {
		
		//Reutilizamos el getClaims(String token)
		Object roles = getClaims(token).get("authorities");
		//Los roles vienen en formato json y hay que pasarlos a Collection<? extends GrantedAuthority>
		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		
		return authorities;
	}

	@Override
	public String resolve(String token) {
		if (token != null & token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");
		}else {
			
			return null;
		}
		
	}

}
