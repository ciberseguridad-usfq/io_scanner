import socket
import nmap
import csv
import sqlite3
import base64
from datetime import datetime
from io import BytesIO
import matplotlib
import numpy as np
from reportlab.lib.enums import TA_CENTER

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
import os
from datetime import datetime
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
)
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import cm
from reportlab.lib import colors
from ipaddress import ip_network
import socket

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
# --- Constants & Database setup ---
DATABASE = 'scan_results.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            hostname TEXT,
            port INTEGER,
            state TEXT,
            service TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_to_db(ip, hostname, port, state, service, scan_date=None):
    if scan_date is None:
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # ✅ Usa fecha actual si no se provee

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO scan_results (ip, hostname, port, state, service, scan_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, hostname, port, state, service, scan_date))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error al guardar en la base de datos: {e}")
    finally:
        conn.close()

# --- Utility functions ---
def nslookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ''

def check_single_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        result = sock.connect_ex((ip, port))
        return 'ABIERTO' if result == 0 else 'CERRADO'
    finally:
        sock.close()

def parse_nmap_output(nm, ip):
    ports = []
    for proto in nm[ip].all_protocols():
        for p in nm[ip][proto].keys():
            state   = nm[ip][proto][p]['state']
            service = nm[ip][proto][p]['name']
            ports.append({'port': p, 'state': state, 'service': service})
    return ports

def get_latest_ports_for_ip(ip):
    """
    Recupera el estado más reciente de cada puerto escaneado para la IP dada.
    Devuelve lista de tuplas (port, state).
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        "SELECT port, state FROM scan_results "
        "WHERE ip=? ORDER BY scan_date DESC",
        (ip,)
    )
    rows = c.fetchall()
    conn.close()

    seen = set()
    latest = []
    for port, state in rows:
        if port not in seen:
            seen.add(port)
            latest.append((port, state))
    return latest

# --- Exporters ---
def export_to_txt(results, filename, from_date=None, to_date=None):
    """
    Exporta resultados a TXT. Opcionalmente filtra por rango de fechas.
    """
    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        dt = datetime.strptime(scan_date.split('.')[0], '%Y-%m-%d %H:%M:%S')
        after_from = True if not from_date else dt >= from_date
        before_to = True if not to_date else dt <= to_date
        return after_from and before_to

    with open(filename, 'w') as f:
        for entry in results:
            # Asumimos que entry['scan_date'] existe si viene de grouped_results
            scan_date = entry.get('scan_date', 'Fecha no disponible')
            if from_date or to_date:
                try:
                    if not in_date_range(scan_date):
                        continue
                except:
                    continue  # si no se puede parsear, salta

            f.write(f"IP: {entry['ip']} ({entry['hostname']})\n")
            for p in entry['ports']:
                f.write(f"  Port {p['port']}: {p['state']} ({p['service']})\n")
            f.write('\n')


def export_to_csv(results, filename, from_date=None, to_date=None):
    """
    Exporta resultados a CSV con filtro opcional por fechas.
    """
    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        try:
            dt = datetime.strptime(scan_date.split('.')[0], '%Y-%m-%d %H:%M:%S')
            after_from = True if not from_date else dt >= from_date
            before_to = True if not to_date else dt <= to_date
            return after_from and before_to
        except:
            return False  # si no se puede parsear, excluye

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Hostname', 'Puerto', 'Estado', 'Servicio', 'Fecha'])

        for entry in results:
            scan_date = entry.get('scan_date', 'Fecha no disponible')
            if from_date or to_date:
                if not in_date_range(scan_date):
                    continue

            for p in entry['ports']:
                writer.writerow([
                    entry['ip'],
                    entry['hostname'],
                    p['port'],
                    p['state'],
                    p['service'],
                    scan_date
                ])


def generate_pdf(results, filename_or_buffer, from_date=None, to_date=None):
    """
    Genera PDF con logo, título y tabla.
    Opcionalmente filtra por rango de fechas.
    """

    def in_date_range(scan_date):
        if not from_date and not to_date:
            return True
        if not scan_date:
            return False

        if isinstance(scan_date, datetime):
            dt = scan_date
        else:
            try:
                clean_str = scan_date.split('.')[0]
                dt = datetime.strptime(clean_str, '%Y-%m-%d %H:%M:%S')
            except Exception:
                return False  # Fecha inválida

        after_from = True if not from_date else dt >= from_date
        before_to = True if not to_date else dt <= to_date
        return after_from and before_to

    doc = SimpleDocTemplate(filename_or_buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()

    # --- Logo ---
    logo_path = os.path.join(os.path.dirname(__file__), 'static', 'logo_usfq.png')
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=5 * cm, height=1.5 * cm)
        logo.hAlign = 'CENTER'
        story.append(logo)
        story.append(Spacer(1, 12))

    # --- Título ---
    title_style = ParagraphStyle(
        'TitleCentered',
        parent=styles['Title'],
        alignment=TA_CENTER,
        fontSize=16,
        spaceAfter=12
    )
    story.append(Paragraph("Resultados del Escaneo de Puertos", title_style))
    story.append(Spacer(1, 12))

    # --- Tabla ---
    data = [['IP', 'Hostname', 'Puerto', 'Estado', 'Servicio', 'Fecha']]
    for entry in results:
        raw_scan_date = entry.get('scan_date')

        # Convertir a string para mostrar, incluso si es datetime
        if isinstance(raw_scan_date, datetime):
            display_date = raw_scan_date.strftime('%Y-%m-%d %H:%M:%S')
        elif raw_scan_date:
            # Asegurarse de quitar microsegundos para mostrar
            display_date = raw_scan_date.split('.')[0]
        else:
            display_date = 'Fecha no disponible'

        # Filtrar usando la función in_date_range
        if from_date or to_date:
            if not in_date_range(raw_scan_date):  # Usa el valor original (str o datetime)
                continue

        ip = entry.get('ip', '')
        hostname = entry.get('hostname', '')
        for p in entry.get('ports', []):
            data.append([
                ip,
                hostname,
                str(p.get('port', '')),
                p.get('state', ''),
                p.get('service', ''),
                display_date  # Ya limpio para mostrar
            ])

    table = Table(data, repeatRows=1, hAlign='LEFT')
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4CAF50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
    ]))
    story.append(table)

    doc.build(story)
# --- Stats & Charts ---
def get_port_stats():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM scan_results")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE state='ABIERTO'")
    open_ports = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scan_results WHERE state='CERRADO'")
    closed_ports = c.fetchone()[0]
    c.execute(
        "SELECT port, service, COUNT(*) as cnt "
        "FROM scan_results WHERE state='ABIERTO' "
        "GROUP BY port, service ORDER BY cnt DESC LIMIT 10"
    )
    top = c.fetchall()
    conn.close()
    return {
        'total_ports': total,
        'open_ports': open_ports,
        'closed_ports': closed_ports,
        'top_ports': top
    }

def create_port_chart():
    stats = get_port_stats()
    labels = ['Abiertos','Cerrados']
    sizes  = [stats['open_ports'], stats['closed_ports']]
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%')
    buf = BytesIO()
    plt.tight_layout()
    fig.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)
    return base64.b64encode(buf.read()).decode('utf-8')

# web_scanner.py
# web_scanner.py
def create_bar_chart(ip, ports=None, scan_date=None):
    """
    Dibuja barras para una IP.
    - Si 'ports' (lista de dicts {'port','state'}) viene desde la plantilla,
      grafica SOLO esos puertos (el resultado visible).
    - Si no viene, mantiene el modo histórico (último estado por puerto) y,
      opcionalmente, permite filtrar por 'scan_date' (LIKE).
    """
    try:
        if ports is not None:
            all_ports = [(p['port'], p['state']) for p in ports]
        else:
            if scan_date:
                conn = sqlite3.connect(DATABASE)
                c = conn.cursor()
                c.execute("""
                    SELECT port, state FROM scan_results
                    WHERE ip = ? AND scan_date LIKE ?
                    ORDER BY port
                """, (ip, f"{scan_date}%"))
                all_ports = c.fetchall()
                conn.close()
            else:
                all_ports = get_latest_ports_for_ip(ip)
    except Exception:
        all_ports = []

    # Si 'ports' viene desde la vista, no inventar "importantes"
    filtered = all_ports[:] if ports is not None else all_ports[:]
    max_bars = 5
    if len(filtered) > max_bars:
        filtered = filtered[:max_bars]  # p. ej., prioriza abiertos y “importantes”

    # Render
    fig, ax = plt.subplots(figsize=(8, 4))
    if not filtered:
        ax.text(0.5, 0.5, f'No hay puertos para {ip}', ha='center', va='center', fontsize=14, color='gray')
        ax.axis('off')
    else:

        labels = [f"{p}\n{state}" for p, state in filtered]
        colors = ['#4CAF50' if s == 'ABIERTO' else '#F44336' if s == 'CERRADO' else '#FFC107' for _, s in filtered]
        ax.bar(labels, [1]*len(labels), color=colors)
        ax.set_yticks([])
        ax.set_title(f'Puertos – {ip}', fontsize=16)
        plt.setp(ax.get_xticklabels(), fontsize=12)
        plt.tight_layout(pad=3.0)



    buf = BytesIO()
    fig.savefig(buf, format='png', dpi=100, bbox_inches='tight')
    buf.seek(0)
    img_b64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    plt.close(fig)
    return img_b64

# --- Core scan logic ---
def scan_ips(ips, specific_port=10050, run_nmap_scan=False, full_nmap_scan=False):
    nm = nmap.PortScanner()
    results = []

    for ip in ips:
        print(f"\n[+] Procesando IP: {ip}")
        entry = {'ip': ip, 'hostname': nslookup(ip), 'ports': []}

        # Puerto específico
        if specific_port is not None:
            state = check_single_port(ip, specific_port)
            entry['ports'].append({
                'port': specific_port,
                'state': state,
                'service': 'zabbix-agent'
            })
            save_to_db(ip, entry['hostname'], specific_port, state, 'zabbix-agent')

        # Nmap
        if run_nmap_scan or full_nmap_scan:
            port_range = '1-65535' if full_nmap_scan else '1-1024'
            nm.scan(ip, port_range, arguments='-Pn')
            ports = parse_nmap_output(nm, ip)
            for p in ports:
                if p['port'] == specific_port:
                    continue
                entry['ports'].append(p)
                save_to_db(ip, entry['hostname'], p['port'], p['state'], p['service'])

        results.append(entry)

    return results

# --- If executed directly ---
if __name__ == "__main__":
    init_db()
    print("Base de datos inicializada en", DATABASE)