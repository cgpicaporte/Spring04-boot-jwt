package com.cgpicaporte.springboot.app.models.service;

import java.io.IOException;
import java.net.MalformedURLException;

import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

public interface IUploadFileService {

	public Resource load(String filename) throws MalformedURLException;

	public String copy(MultipartFile file) throws IOException;

	public boolean delete(String filename);

	//por si queremos borrar y crear el directorio uploads cada vez que iniciemos la aplicación
	//debemos en public class Spring03BootDataJpaApplication implementar la interfaz CommandLineRunner con los siguientes metodos {
	//public void deleteAll();
	//public void init() throws IOException;
		
}
