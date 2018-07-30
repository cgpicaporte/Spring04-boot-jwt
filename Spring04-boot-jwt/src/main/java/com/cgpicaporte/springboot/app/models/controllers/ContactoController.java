package com.cgpicaporte.springboot.app.models.controllers;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;
import com.cgpicaporte.springboot.app.models.service.ICocheService;
import com.cgpicaporte.springboot.app.models.service.IContactoService;

@EnableGlobalMethodSecurity(securedEnabled=true)
@Controller
@RequestMapping("/contacto")
@SessionAttributes("contacto")
public class ContactoController {

	private final Logger log = LoggerFactory.getLogger(getClass());
	
	@Autowired
	private ICocheService cocheService;
	
	@Autowired
	private IContactoService contactoService;
	
	
	@GetMapping("/form/{cocheId}")
	public String crear(@PathVariable(value="cocheId") Long cocheId, @RequestParam(name = "page", defaultValue = "0") int page, Map<String, Object> model, RedirectAttributes flash) {
		
		Coche coche = cocheService.findOne(cocheId);
		if(coche == null) {
			flash.addFlashAttribute("error", "El coche no existe en la base de datos.");
			return "redirect:/listar";
		}
		
		Contacto contacto = new Contacto();
		contacto.setCoche(coche);
		
		model.put("contacto", contacto);
		model.put("titulo", "Interesado por...");
		model.put("titulo2", "Crear contacto");
		model.put("pagina", page);
		
		return "contacto/form";
	}
	
	//@ResponseBody -> transforma la respuesta y la guarda como json en el body de la respuesta
	@GetMapping(value="/cargar-coches/{term}", produces= {"application/json"})
	public @ResponseBody List<Coche> cargarCoches(@PathVariable String term){
		return cocheService.findByMarca(term);
	}
	
	@PostMapping("/form")
	public String guardar(@Valid Contacto contacto, @RequestParam(name = "page", defaultValue = "0") int page, Map<String, Object> model, RedirectAttributes flash, SessionStatus status) {
		
		
		/*
		String mensajeFlash = (contacto.getCoche().getId() != null) ? "El contacto se ha editado con éxito."
				: "El contacto se ha creado con éxito.";
		*/

		String mensajeFlash = "El contacto se ha creado con éxito.";

		//log.info("mensajeFlash: "+ mensajeFlash);
		
		Coche coche = contacto.getCoche();
		
		//log.info("contacto.getCoche().getId(): "+ contacto.getCoche().getId());
				
		List<Contacto> lContactos = coche.getContactos();
		
		if (lContactos == null || lContactos.isEmpty()) {
			
			lContactos = new ArrayList<Contacto>();
			//log.info("Creando array de contactos ...");
		}
		
		/*
		for(Contacto c:lContactos) {
			System.out.println(c.getNombre());
		}
		*/
				
		lContactos.add(contacto);
		
		coche.setContactos(lContactos);
		
		cocheService.save(coche);
		
		model.put("pagina", page);
		model.put("titulo", "FORMULARIO INTERESADO POR VEHÍCULO");
		
				
		status.setComplete();// elimina el objeto contacto de la session
		flash.addFlashAttribute("success", mensajeFlash);
		//return "redirect:/inicio?pagina="+page;
		return "contacto/contactoGuardado";
	}
	
	@GetMapping("/contactoGuardado")
	public String contactoGuardado(@RequestParam(name = "page", defaultValue = "0") int page, RedirectAttributes flash, SessionStatus status) {
						
		String mensajeFlash = "El contacto se ha creado con éxito.";
		log.info("mensajeFlash: "+ mensajeFlash);
			
		status.setComplete();
		flash.addFlashAttribute("success", mensajeFlash);
		
		return "redirect:inicio?page="+page;
	}
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/eliminar/{id}/{idContact}")
	public String eliminarContacto(@PathVariable(value = "id") Long id, @PathVariable(value = "idContact") Long idContact, Map<String, Object> model, RedirectAttributes flash) {

		Coche coche = null;
		
		if (id > 0) {
			
			coche = cocheService.findOne(id);

			if (idContact > 0 && coche!=null) {
				
				Contacto contacto = contactoService.findOne(idContact);
				contactoService.detete(contacto.getId());
				flash.addFlashAttribute("success", "El contacto se ha eliminado.");
				
			} 
			
		}

		return "redirect:/ver/"+coche.getId();
	}
}
