package com.cgpicaporte.springboot.app.view.xslx;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.document.AbstractXlsxView;

import com.cgpicaporte.springboot.app.models.entity.Coche;
import com.cgpicaporte.springboot.app.models.entity.Contacto;

@Component("ver.xlsx")
public class InteresadosXlsxView extends AbstractXlsxView {

	@Override
	protected void buildExcelDocument(Map<String, Object> model, Workbook workbook, HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		response.setHeader("Content-Disposition", "attachment; filename=\"coche_interesados_view.xlsx\"");
		Coche coche = (Coche) model.get("coche");
		Sheet sheet = workbook.createSheet("Coche Interesados Spring");

		// MessageSourceAccessor mensajes = getMessageSourceAccessor();

		Row row = sheet.createRow(0);
		Cell cell = row.createCell(0);
		cell.setCellValue("Datos del coche");

		row = sheet.createRow(1);
		cell = row.createCell(0);
		cell.setCellValue(coche.getMarca() + " " + coche.getModelo());

		row = sheet.createRow(2);
		cell = row.createCell(0);
		cell.setCellValue("Precio: " + coche.getPrecio());

		row = sheet.createRow(3);
		cell = row.createCell(0);
		cell.setCellValue("Kilómetros: " + coche.getKilometros());

		if (!coche.getContactos().isEmpty() && coche.getContactos().size() > 0) {

			sheet.createRow(5).createCell(0).setCellValue("Interesados en el vehículo");

			CellStyle theaderStyle = workbook.createCellStyle();
			theaderStyle.setBorderBottom(BorderStyle.MEDIUM);
			theaderStyle.setBorderTop(BorderStyle.MEDIUM);
			theaderStyle.setBorderRight(BorderStyle.MEDIUM);
			theaderStyle.setBorderLeft(BorderStyle.MEDIUM);
			theaderStyle.setFillForegroundColor(IndexedColors.GOLD.index);
			theaderStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);

			CellStyle tbodyStyle = workbook.createCellStyle();
			tbodyStyle.setBorderBottom(BorderStyle.THIN);
			tbodyStyle.setBorderTop(BorderStyle.THIN);
			tbodyStyle.setBorderRight(BorderStyle.THIN);
			tbodyStyle.setBorderLeft(BorderStyle.THIN);
			
			Row header = sheet.createRow(5);
			header.createCell(0).setCellValue("Nombre");
			header.createCell(1).setCellValue("Email");
			header.createCell(2).setCellValue("Teléfono");
			header.createCell(3).setCellValue("Mensaje");

			header.getCell(0).setCellStyle(theaderStyle);
			header.getCell(1).setCellStyle(theaderStyle);
			header.getCell(2).setCellStyle(theaderStyle);
			header.getCell(3).setCellStyle(theaderStyle);

			int rownum = 6;

			for (Contacto contacto : coche.getContactos()) {
				Row fila = sheet.createRow(rownum++);
				cell = fila.createCell(0);
				cell.setCellValue(contacto.getNombre());
				cell.setCellStyle(tbodyStyle);

				cell = fila.createCell(1);
				cell.setCellValue(contacto.getEmail());
				cell.setCellStyle(tbodyStyle);

				cell = fila.createCell(2);
				cell.setCellValue(contacto.getTelefono());
				cell.setCellStyle(tbodyStyle);

				cell = fila.createCell(3);
				cell.setCellValue(contacto.getMensaje());
				cell.setCellStyle(tbodyStyle);
			}

		}

		// Row filatotal = sheet.createRow(rownum);
		// cell = filatotal.createCell(2);
		// cell.setCellValue(mensajes.getMessage("text.factura.form.total") + ": ");
		// cell.setCellStyle(tbodyStyle);
		//
		// cell= filatotal.createCell(3);
		// cell.setCellValue(factura.getTotal());
		// cell.setCellStyle(tbodyStyle);
		//
	}

}
