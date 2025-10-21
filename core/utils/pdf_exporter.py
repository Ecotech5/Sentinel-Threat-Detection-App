# utils/pdf_exporter.py
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas
from PIL import Image

DEFAULT_EXPORT_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(DEFAULT_EXPORT_DIR, exist_ok=True)


def export_report_pdf(title: str, summary: dict, full_text: str, filename: str = None, logo_path: str = None) -> str:
    if not filename:
        filename = f"sentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(DEFAULT_EXPORT_DIR, filename)

    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter

    # Header: optional logo
    y = height - 20 * mm
    x_offset = 20 * mm
    if logo_path and os.path.exists(logo_path):
        try:
            im = Image.open(logo_path)
            target_w = 30 * mm
            ratio = target_w / im.size[0]
            target_h = im.size[1] * ratio
            c.drawImage(logo_path, x_offset, y - target_h, width=target_w, height=target_h, preserveAspectRatio=True)
            x_offset += target_w + 6 * mm
        except Exception:
            pass

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x_offset, y, title)
    c.setFont("Helvetica", 9)
    c.drawString(x_offset, y - 14, f"Generated: {datetime.now().isoformat(sep=' ', timespec='seconds')}")

    # Summary box
    sy = y - 36
    c.setFont("Helvetica-Bold", 11)
    c.drawString(20 * mm, sy, "Threat Summary")
    c.setFont("Helvetica", 10)
    sy -= 14
    for k, v in summary.items():
        c.drawString(22 * mm, sy, f"{k}: {v}")
        sy -= 12

    # Full text
    by = sy - 10
    c.setFont("Helvetica", 9)
    lines = full_text.splitlines()
    for line in lines:
        if by < 30:
            c.showPage()
            by = height - 36
            c.setFont("Helvetica", 9)
        c.drawString(20 * mm, by, line[:120])
        by -= 11

    c.save()
    return path
