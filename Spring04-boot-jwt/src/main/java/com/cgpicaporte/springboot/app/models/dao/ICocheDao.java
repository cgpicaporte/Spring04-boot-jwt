package com.cgpicaporte.springboot.app.models.dao;

//import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

import com.cgpicaporte.springboot.app.models.entity.Coche;

public interface ICocheDao  extends PagingAndSortingRepository<Coche, Long> {
	
}
