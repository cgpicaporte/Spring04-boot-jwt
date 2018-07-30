package com.cgpicaporte.springboot.app.models.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.cgpicaporte.springboot.app.models.service.ICocheService;
import com.cgpicaporte.springboot.app.view.xml.CocheList;

@RestController
@RequestMapping("/api/coches")
public class CocheRestController {

	@Autowired
	private ICocheService cocheService;
	
	@Secured("ROLE_ADMIN")
	@GetMapping(value = "/listar")
	public @ResponseBody CocheList listarRest() {
		return new CocheList(cocheService.findAll());
	}
	
}
