package com.cgpicaporte.springboot.app.models.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cgpicaporte.springboot.app.models.dao.IContactoDao;
import com.cgpicaporte.springboot.app.models.entity.Contacto;

@Service
public class ContactoServiceImpl implements IContactoService {

	@Autowired
	private IContactoDao contactoDao;
	
	@Override
	@Transactional
	public void detete(Long id) {
		contactoDao.deleteById(id);
	}
	
	@Override
	@Transactional(readOnly=true)
	public Contacto findOne(Long id) {
		return contactoDao.findById(id).orElse(null);
	}

}
