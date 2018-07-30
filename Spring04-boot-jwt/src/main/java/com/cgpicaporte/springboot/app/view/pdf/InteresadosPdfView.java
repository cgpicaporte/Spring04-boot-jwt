package com.cgpicaporte.springboot.app.view.pdf;

import java.awt.Color;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractPdfView;

import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;
import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;

@Component("ver")
public class InteresadosPdfView extends AbstractPdfView {

	@Override
	protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer, HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		//Obtenemos el coche del modelo y los interesados o contactos
		Coche coche = (Coche) model.get("coche");
		List<Contacto> contactos = coche.getContactos();
		
		PdfPTable tabla = new PdfPTable(1);
		tabla.setSpacingAfter(20);
		
		PdfPCell cell = null;
		cell = new PdfPCell(new Phrase("DETALLE COCHE: ".concat(coche.getMarca().concat(" ").concat(coche.getModelo()))));
		cell.setBackgroundColor(new Color(0, 123, 255));
		cell.setPadding(8f);
		cell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
		
		tabla.addCell(cell);
		tabla.addCell("MARCA: ".concat(coche.getMarca()));
		tabla.addCell("PRECIO: ".concat(coche.getPrecio().toString()));
		tabla.addCell("MODELO: ".concat(coche.getModelo()));
		tabla.addCell("FUEL: ".concat(coche.getCombustible()));
		tabla.addCell("KM: ".concat(new Integer(coche.getKilometros()).toString()));
		tabla.addCell("AÑO: ".concat(new Integer(coche.getAno()).toString()));
		tabla.addCell("CAMBIO: ".concat(coche.getCambio()));
		tabla.addCell("PLAZAS: ".concat(new Integer(coche.getPlazas()).toString()));
		tabla.addCell("PUERTAS: ".concat(new Integer(coche.getPuertas()).toString()));
		tabla.addCell("CV: ".concat(new Integer(coche.getPotencia()).toString()));
		tabla.addCell("COLOR: ".concat(coche.getColor()));
		tabla.addCell("GARANTÍA: ".concat(coche.getGarantia()));
		tabla.addCell("FECHA: ".concat(coche.getCreateAt().toString()));
		
		PdfPTable tabla2 = null;
		PdfPTable tabla3 = null;
		PdfPTable tabla4 = null;
		
		if(!contactos.isEmpty()) {
			tabla2 = new PdfPTable(5);
			cell = new PdfPCell(new Phrase("INTERESADOS EN EL VEHÍCULO"));
			cell.setBackgroundColor(new Color(0, 123, 255));
			cell.setPadding(8f);
			cell.setColspan(5);
			cell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
			tabla2.addCell(cell);
			
			tabla3 = new PdfPTable(5);
			tabla3.setWidths(new float [] {2.5f,1,1,1,1});
			tabla3.setSpacingAfter(20);
			tabla3.addCell("Nombre");
			tabla3.addCell("Email");
			tabla3.addCell("Teléfono");
			tabla3.addCell("Fecha");
			tabla3.addCell("Mensaje");
			
			tabla4 = new PdfPTable(5);
				
			for (Contacto contacto : contactos) {
				tabla3.addCell(contacto.getNombre());
				tabla3.addCell(contacto.getEmail());
				tabla3.addCell(contacto.getTelefono());
				tabla3.addCell(contacto.getCreateAt().toString());
				tabla3.addCell(contacto.getMensaje());
			}
		
		}
		
		document.add(tabla);
		
		if(!contactos.isEmpty()) {
			
			document.add(tabla2);
			document.add(tabla3);
			document.add(tabla4);
		}
		
		
		
	}

}
