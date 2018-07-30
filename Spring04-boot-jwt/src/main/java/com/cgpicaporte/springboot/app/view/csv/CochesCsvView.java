package com.cgpicaporte.springboot.app.view.csv;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.AbstractView;
import org.supercsv.io.CsvBeanWriter;
import org.supercsv.io.ICsvBeanWriter;
import org.supercsv.prefs.CsvPreference;

import com.cgpicaporte.springboot.app.models.entity.Coche;

@Component("listar.csv")
public class CochesCsvView extends AbstractView{

	public CochesCsvView() {
		setContentType("text/csv");
	}

	@Override
	protected boolean generatesDownloadContent() {
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		response.setHeader("Content-Disposition", "attachment; filename=\"coches.csv\"");
		response.setContentType(getContentType());
		
		Page<Coche> coches = (Page<Coche>) model.get("coches");
		
		ICsvBeanWriter beanWriter = new CsvBeanWriter(response.getWriter(),  CsvPreference.STANDARD_PREFERENCE);
		
		String[] header = {"id", "precio", "marca", "modelo", "provincia", "kilometros", "ano", "publicado"};
		beanWriter.writeHeader(header);
		
		for(Coche coche: coches) {
			beanWriter.write(coche, header);
		}
		
		beanWriter.close();
	}
	
}
