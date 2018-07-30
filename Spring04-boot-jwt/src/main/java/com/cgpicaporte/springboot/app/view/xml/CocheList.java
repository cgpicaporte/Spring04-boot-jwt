package com.cgpicaporte.springboot.app.view.xml;

import java.util.List;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

import com.cgpicaporte.springboot.app.models.entity.Coche;

@XmlRootElement(name="cochesList")
public class CocheList {

	@XmlElement(name="coche")
	public List<Coche> coches;

	public CocheList() {
		
	}

	public CocheList(List<Coche> coches) {
		this.coches = coches;
	}

	public List<Coche> getCoches() {
		return coches;
	}
	
	
	
	
	
}
