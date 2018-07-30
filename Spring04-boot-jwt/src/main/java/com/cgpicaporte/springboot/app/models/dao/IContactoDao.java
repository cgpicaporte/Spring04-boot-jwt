package com.cgpicaporte.springboot.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.cgpicaporte.springboot.app.models.entity.Contacto;

public interface IContactoDao extends CrudRepository<Contacto, Long> {

}
