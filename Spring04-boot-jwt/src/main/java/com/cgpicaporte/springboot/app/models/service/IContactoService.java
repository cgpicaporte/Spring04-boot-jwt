package com.cgpicaporte.springboot.app.models.service;

import com.cgpicaporte.springboot.app.models.entity.Contacto;

public interface IContactoService {

	public void detete(Long id);

	public Contacto findOne(Long id);
	
}
