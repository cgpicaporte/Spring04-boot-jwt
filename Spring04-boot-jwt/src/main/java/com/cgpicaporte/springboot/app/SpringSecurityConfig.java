package com.cgpicaporte.springboot.app;

//import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;

import com.cgpicaporte.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.cgpicaporte.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.cgpicaporte.springboot.app.auth.service.JWTService;
//import com.cgpicaporte.springboot.app.auth.handler.LoginSuccessHandler;
import com.cgpicaporte.springboot.app.models.service.JpaUserDetailsService;

@Configuration
public class SpringSecurityConfig  extends WebSecurityConfigurerAdapter{
	
	//Comentado al comentar el login
	//@Autowired
	//private LoginSuccessHandler successHandler;
	
	//Por CASO 2
	/*
	@Autowired
	private DataSource dataSource;
	*/
	
	//Por CASO 3
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	//Inyectamos JWTService y lo añadimos al filtro -> new JWTAuthenticationFilter(authenticationManager())
	@Autowired
	private JWTService jwtService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/inicio/**", "/ver/**", "/uploads/**",
				"/contacto/form/**", "/contacto/contactoGuardado/**", "/contacto/cargar-coches/**", "/form/**", "/locale").permitAll()
		/*.antMatchers("/listar").hasAnyRole("ADMIN")
		.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
		.antMatchers("/contacto/eliminar/**").hasAnyRole("ADMIN")
		*/
		.anyRequest().authenticated()
		/*.and()
		    .formLogin()
		        .successHandler(successHandler)
		        .loginPage("/login")
		    .permitAll()
		.and()
		.logout().permitAll()
		.and()
		.exceptionHandling().accessDeniedPage("/error_403")*/
		.and()
		//.addFilter(new JWTAuthenticationFilter(authenticationManager()))
		.addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtService))
		.addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
	}

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception{
		
		//CASO 1: COMENTAMOS EL PRIMER METODO DE IN MEMORY AUTHENTICATION
		/*
		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		UserBuilder users = User.builder().passwordEncoder(encoder::encode);
		
		build.inMemoryAuthentication()
			.withUser(users.username("admin").password("admin").roles("ADMIN", "USER"))
			.withUser(users.username("cgpicaporte").password("3500").roles("USER"));
		*/
		
		//CASO 2: POR jdbc Authentication
		/*
		build.jdbcAuthentication()
		.dataSource(dataSource)
		.passwordEncoder(passwordEncoder)
		.usersByUsernameQuery("select username, password, enabled from users where username=?")
		.authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");
		*/
		
		//CASO3: por Jpa
		build.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
		
		
	}
}
