package com.cgpicaporte.springboot.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.cgpicaporte.springboot.app.models.entity.Coche;

public interface IContactoCocheDao extends CrudRepository<Coche, Long> {
	
	//from Coche se refiere a la clase Entity Coche
	
	@Query("select c from Coche c where c.marca like %?1%")
	public List<Coche> findByMarca(String term);
	
}
