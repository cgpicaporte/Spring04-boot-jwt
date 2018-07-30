package com.cgpicaporte.springboot.app.models.controllers;

//import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Collection;
import java.util.Locale;
//import java.util.List;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
import java.util.Map;
//import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.core.io.Resource;
//import org.springframework.core.io.UrlResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestWrapper;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;
import com.cgpicaporte.springboot.app.models.service.ICocheService;
import com.cgpicaporte.springboot.app.models.service.IUploadFileService;
import com.cgpicaporte.springboot.app.models.util.paginator.PageRender;
import com.cgpicaporte.springboot.app.view.xml.CocheList;

@EnableGlobalMethodSecurity(securedEnabled=true)
@Controller
@SessionAttributes("coche")
public class CocheController {

	protected final Log logger = LogFactory.getLog(this.getClass());
	
	@Autowired
	private ICocheService cocheService;

	@Autowired
	private IUploadFileService uploadFileService;
	
	@Autowired
	private MessageSource messageSource;

	//Pasado a UploadService
	//private final Logger log = LoggerFactory.getLogger(getClass());
	//private String UPLOADS_FOLDER = "uploads";

	/* {filename:.+} -> expresion regular para no perder la extensión del fichero */
	@GetMapping(value = "/uploads/{filename:.+}")
	public ResponseEntity<Resource> verFoto(@PathVariable String filename) {

		Resource recurso = null;

		try {
			recurso = uploadFileService.load(filename);
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + recurso.getFilename() + "\"")
				.body(recurso);
	}

	@GetMapping(value = "/ver/{id}")
	public String ver(@PathVariable(value = "id") Long id, @RequestParam(name = "page", defaultValue = "0") int page,
			Map<String, Object> model, RedirectAttributes flash) {

		Coche coche = cocheService.findOne(id);
		if (coche == null) {
			flash.addFlashAttribute("error", "El coche no existe en la base de datos.");
			return "redirect:/inicio";
		}

		model.put("coche", coche);
		model.put("titulo", "DETALLE COCHE: " + coche.getMarca() + " " + coche.getModelo());
		model.put("pagina", page);

		return "ver";
	}
	
	/*
	@Secured("ROLE_ADMIN")
	@GetMapping(value = "/listar-rest")
	public @ResponseBody List<Coche> listarRest() {
		return cocheService.findAll();
	}
	*/
	
	//@Secured("ROLE_ADMIN")
	@GetMapping(value = "/listar-rest")
	public @ResponseBody CocheList listarRest() {
		return new CocheList(cocheService.findAll());
	}
	
	
	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/listar", method = RequestMethod.GET)
	//public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model, Authentication authentication) {
	//public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model, Authentication authentication, HttpServletRequest request) {
	//Añadimos el locale para las traducciones
	public String listar(@RequestParam(name = "page", defaultValue = "0") int page, Model model, Authentication authentication, HttpServletRequest request, Locale locale) {	
		
		
		if (authentication != null) {
			logger.info("Hola usuario autenticado, tu username es: ".concat(authentication.getName()));			
		}
		
		//Para obtenerlo de forma estática
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth != null) {
			logger.info("Utilizando forma estática SecurityContextHolder.getContext().getAuthentication(): Hola usuario autenticado, username es: ".concat(auth.getName()));
		}
		
		if (hasRole("ROLE_ADMIN")) {
			logger.info("Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}

		//SecurityContextHolderAwareRequestWrapper añado al metodo listar el HttpServletRequest
		SecurityContextHolderAwareRequestWrapper securityContext = new SecurityContextHolderAwareRequestWrapper(request, "ROLE_");
		if(securityContext.isUserInRole("ADMIN")) {
			logger.info("Forma usando SecurityContextHolderAwareRequestWrapper: Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Forma usando SecurityContextHolderAwareRequestWrapper: Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}
		
		//Con el HttpServletRequest request añadiendo prefijo
		if(request.isUserInRole("ROLE_ADMIN")) {
			logger.info("Forma usando HttpServletRequest: Hola ".concat(auth.getName()).concat(" tienes acceso!"));
		}else {
			logger.info("Forma usando HttpServletRequest: Hola ".concat(auth.getName()).concat(" NO tienes acceso!"));
		}
		
		Pageable pageRequest = PageRequest.of(page, 6);
		Page<Coche> coches = cocheService.findAll(pageRequest);
		PageRender<Coche> pageRender = new PageRender<Coche>("/listar", coches);

		model.addAttribute("titulo", messageSource.getMessage("text.coche.listar.titulo",null, locale));
		model.addAttribute("coches", coches);
		model.addAttribute("page", pageRender);
		model.addAttribute("pagina", page);
		return "listar";
	}

	@RequestMapping(value = {"/inicio","/"}, method = RequestMethod.GET)
	public String inicio(@RequestParam(name = "page", defaultValue = "0") int page, Model model) {

		Pageable pageRequest = PageRequest.of(page, 6);
		Page<Coche> coches = cocheService.findAll(pageRequest);
		PageRender<Coche> pageRender = new PageRender<Coche>("/inicio", coches);

		model.addAttribute("titulo", "COCHES PARTICULARES");
		model.addAttribute("coches", coches);
		model.addAttribute("page", pageRender);
		model.addAttribute("pagina", page);
		return "inicio";
	}

	@RequestMapping(value = "/form")
	public String crear(Map<String, Object> model) {

		Coche coche = new Coche();
		model.put("titulo", "FORMULARIO VENDEDOR COCHE");
		model.put("coche", coche);

		return "form";
	}
	
	@RequestMapping(value = "/contacto")
	public String crearContacto(Map<String, Object> model) {

		Contacto contacto = new Contacto();
		model.put("titulo", "Formulario de Contacto");
		model.put("contacto", contacto);

		return "contacto";
	}

	@RequestMapping(value = "/form", method = RequestMethod.POST)
	public String guardar(@Valid Coche coche, BindingResult result, Model model,
			@RequestParam("file") MultipartFile foto, RedirectAttributes flash, SessionStatus status){

		if (result.hasErrors()) {
			model.addAttribute("titulo", "FORMULARIO COCHE");
			return "form";
		}

		if (!foto.isEmpty()) {

			/* Si existe una foto la eliminamos y subimos la nueva */
			if (coche.getId() != null 
					&& coche.getId() > 0 
					&& coche.getFoto() != null 
					&& coche.getFoto().length() > 0) {

				uploadFileService.delete(coche.getFoto());

			}

			/*
			 * SACAMOS EL DIRECTORIO DE SUBIDA DE IMAGENES DEL CONTEXTO DE LA APLICACIÓN Y
			 * LO SUBIMOS AL SERVIDOR File directorio = new
			 * File("src//main/resources//static/uploads/"+coche.getId());
			 * directorio.mkdir(); Path directorioRecursos =
			 * Paths.get(directorio.getAbsolutePath()); String rootPath =
			 * directorioRecursos.toFile().getAbsolutePath();
			 */

			/*
			 * String rootPath = "C:/Temp/uploads/"; File directorio = new File(rootPath +
			 * coche.getId()); directorio.mkdir(); Path directorioRecursos =
			 * Paths.get(directorio.getAbsolutePath()); rootPath =
			 * directorioRecursos.toFile().getAbsolutePath();
			 */

			/*
			 * Agregamos directorio absoluto y externo en al raiz del proyecto
			 * 
			 */

			String uniqueFilename = null;
			try {
				uniqueFilename = uploadFileService.copy(foto);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			flash.addFlashAttribute("info", "Has subido correctamente '" + uniqueFilename + "'");
			coche.setFoto(uniqueFilename);

		}

		String mensajeFlash = (coche.getId() != null) ? "El coche se ha editado con éxito."
				: "El coche se ha creado con éxito. En cuanto validemos los datos aparecerá en esta web.";

		cocheService.save(coche);
		status.setComplete();// elimina el objeto coche de la session
		flash.addFlashAttribute("success", mensajeFlash);
		return "redirect:inicio";
	}

	@RequestMapping(value = "/form/{id}")
	public String editar(@PathVariable(value = "id") Long id, @RequestParam(name = "page", defaultValue = "0") int page,
			Map<String, Object> model, RedirectAttributes flash) {

		Coche coche = null;

		if (id > 0) {
			coche = cocheService.findOne(id);
			if (coche == null) {
				flash.addFlashAttribute("error", "El Id de coche no existe en la BBDD!");
				return "redirect:/listar";
			}
		} else {
			flash.addFlashAttribute("error", "El Id de coche no puede ser 0!");
			return "redirect:/listar";
		}
		model.put("coche", coche);
		model.put("titulo", "EDITAR COCHE");
		model.put("pagina", page);

		return "form";
	}

	@Secured("ROLE_ADMIN")
	@RequestMapping(value = "/eliminar/{id}")
	public String eliminar(@PathVariable(value = "id") Long id, RedirectAttributes flash) {

		if (id > 0) {

			Coche coche = cocheService.findOne(id);

			cocheService.detete(id);
			flash.addFlashAttribute("success", "El coche se ha eliminado.");

			if (uploadFileService.delete(coche.getFoto())) {
				flash.addFlashAttribute("info", "Foto " + coche.getFoto() + " eliminada con exito!");
			}
			
		}

		return "redirect:/listar";
	}
	
		
	
	private boolean hasRole(String role) {
		
		SecurityContext context = SecurityContextHolder.getContext();
		
		if (context == null) {
			return false;
		}
		
		Authentication auth = context.getAuthentication();
		
		if (auth == null) {
			return false;
		}
		
		Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
		
		return authorities.contains(new SimpleGrantedAuthority(role));
		
		/*
		for (GrantedAuthority authority:authorities) {
			if(role.equals(authority.getAuthority())){
				logger.info("Hola usuario ".concat((auth.getName()).concat(" tu rol es: ".concat(authority.getAuthority()))));
				return true;
			}
		}
		
		return false;
		*/		
	}

}
