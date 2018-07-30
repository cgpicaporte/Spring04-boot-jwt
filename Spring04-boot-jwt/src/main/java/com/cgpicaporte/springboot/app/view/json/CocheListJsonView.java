package com.cgpicaporte.springboot.app.view.json;

import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import com.cgpicaporte.springboot.app.models.entity.Coche;

@SuppressWarnings("unchecked")
@Component("listar.json")
public class CocheListJsonView extends MappingJackson2JsonView{

	@Override
	protected Object filterModel(Map<String, Object> model) {

		model.remove("titulo");
		model.remove("page");
		model.remove("pagina");
		model.remove("coche");
		
		Page<Coche> coches = (Page<Coche>) model.get("coches");
		
		model.remove("coches");
		
		model.put("cocheList", coches.getContent());
		
		return super.filterModel(model);
	}

}
