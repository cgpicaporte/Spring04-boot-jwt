package com.cgpicaporte.springboot.app.models.service;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;

public interface ICocheService {

	public List<Coche> findAll();
	
	public Page<Coche> findAll(Pageable pageable);
	
	public void save(Coche coche);
	
	public Coche findOne(Long id);
	
	public void detete(Long id);
	
	public List<Coche> findByMarca(String term);
	
	public void save(Contacto contacto);
		
}
