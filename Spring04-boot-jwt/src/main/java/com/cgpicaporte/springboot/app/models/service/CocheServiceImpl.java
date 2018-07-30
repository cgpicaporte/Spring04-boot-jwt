package com.cgpicaporte.springboot.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
//import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.cgpicaporte.springboot.app.models.dao.ICocheDao;
import com.cgpicaporte.springboot.app.models.dao.IContactoCocheDao;
import com.cgpicaporte.springboot.app.models.dao.IContactoDao;
import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;

@Service
public class CocheServiceImpl implements ICocheService {
	
	//es un facade para el cochesDao
	//Movemos los @Transaccional a esta clase desde la CocheDaoImpl
	//Podemos actuar con diferentes Daos dentro de esta clase Service y en la misma transaccion
	
	@Autowired
	private ICocheDao cochesDao;
	
	@Autowired
	private IContactoCocheDao contactoCocheDao;
	
	@Autowired
	private IContactoDao contactoDao;
	
	@Override
	@Transactional(readOnly=true)
	public List<Coche> findAll() {
		return (List<Coche>) cochesDao.findAll();
	}

	@Override
	@Transactional
	public void save(Coche coche) {
		cochesDao.save(coche);
	}

	@Override
	@Transactional(readOnly=true)
	public Coche findOne(Long id) {
		return cochesDao.findById(id).orElse(null);
	}

	@Override
	@Transactional
	public void detete(Long id) {
		cochesDao.deleteById(id);
	}

	@Override
	public Page<Coche> findAll(Pageable pageable) {
		// TODO Auto-generated method stub
		return cochesDao.findAll(pageable);
	}

	@Override
	public List<Coche> findByMarca(String term) {
		// TODO Auto-generated method stub
		return contactoCocheDao.findByMarca(term);
	}

	@Override
	@Transactional
	public void save(Contacto contacto) {
		// TODO Auto-generated method stub
		contactoDao.save(contacto);
	}

}
