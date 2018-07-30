package com.cgpicaporte.springboot.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//import com.cgpicaporte.springboot.app.models.service.IUploadFileService;

//import com.cgpicaporte.springboot.app.models.service.IUploadFileService;

@SpringBootApplication
public class Spring04BootJWTApplication implements CommandLineRunner{

	//por si queremos borrar y crear el directorio uploads cada vez que iniciemos la aplicación
	//debemos en public class Spring03BootDataJpaApplication implementar la interfaz CommandLineRunner con los siguientes metodos {
	//deleteAll e init
		
	/*
	@Autowired
	IUploadFileService uploadFileService;
	*/
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	public static void main(String[] args) {
		SpringApplication.run(Spring04BootJWTApplication.class, args);
	}

	
	@Override
	public void run(String... arg0) throws Exception {
		// TODO Auto-generated method stub
		//uploadFileService.deleteAll();
		//uploadFileService.init();
		
		String password = "12345";
		
		for(int i=0; i<2; i++) {
			String bcryptPassword = passwordEncoder.encode(password);
			System.out.println(bcryptPassword);
		}
		
	}
	
	
	
}
