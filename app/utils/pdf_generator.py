from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm
from reportlab.graphics import renderPDF
from reportlab.graphics.shapes import Drawing, String
from reportlab.graphics.barcode.qr import QrCodeWidget
import io
from datetime import datetime

def generate_ticket_pdf(ticket, institution_name, service, position, wait_time):
    """
    Gera um PDF para um ticket físico com o layout da imagem fornecida.
    """
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    
    # Configurações de layout
    width, height = A4
    margin = 20 * mm
    center_x = width / 2
    
    # Título: "Sua senha"
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(center_x, height - margin - 20, "Sua senha")
    
    # Nome da instituição
    c.setFont("Helvetica", 14)
    c.drawCentredString(center_x, height - margin - 40, institution_name)
    
    # "Número da senha"
    c.setFont("Helvetica", 12)
    c.drawCentredString(center_x, height - margin - 60, "Número da senha")
    
    # Número da senha (ex.: B1)
    c.setFont("Helvetica-Bold", 40)
    c.drawCentredString(center_x, height - margin - 90, f"{ticket.queue.prefix}{ticket.ticket_number}")
    
    # QR Code
    qr = QrCodeWidget(ticket.qr_code)
    d = Drawing(100, 100)
    d.add(qr)
    renderPDF.draw(d, c, center_x - 50, height - margin - 190)
    
    # Balcão (guichê)
    c.setFont("Helvetica", 12)
    counter_text = f"Balcão: {ticket.counter if ticket.counter else 'Aguardando chamada'}"
    c.drawCentredString(center_x, height - margin - 210, counter_text)
    
    # Posição e Tempo de espera
    c.setFont("Helvetica", 12)
    c.drawCentredString(center_x, height - margin - 230, f"Posição: {position}")
    c.drawCentredString(center_x, height - margin - 250, f"Tempo de espera: {wait_time} minutos")
    
    # Data de emissão e expiração
    c.setFont("Helvetica", 10)
    c.drawCentredString(center_x, height - margin - 270, f"Data de Emissão: {ticket.issued_at.strftime('%d/%m/%Y %H:%M')}")
    if ticket.expires_at:
        c.drawCentredString(center_x, height - margin - 290, f"Expira em: {ticket.expires_at.strftime('%d/%m/%Y %H:%M')}")
    
    c.showPage()
    c.save()
    buffer.seek(0)
    return buffer