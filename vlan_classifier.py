
import sqlite3
import ipaddress
import os

DB_FILE = 'ip_database.db'

def crear_base_datos():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                vlan INTEGER NOT NULL,
                tipo TEXT NOT NULL,
                campus TEXT NOT NULL,
                tercer_octeto INTEGER NOT NULL
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vlan_tipo ON ips(vlan, tipo)')
        conn.commit()
        conn.close()

def clasificar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        octetos = ip.split('.')
        if ip.startswith('172.'):
            return {
                'vlan': int(octetos[2]),
                'tipo': 'Campus',
                'campus': 'Cumbayá',
                'tercer_octeto': int(octetos[2])
            }
        elif ip.startswith('10.'):
            return {
                'vlan': int(octetos[2]),
                'tipo': 'Externo',
                'campus': 'Externo',
                'tercer_octeto': int(octetos[2])
            }
        else:
            return None
    except ValueError:
        return None

def insertar_ips(lista_ips):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for ip in lista_ips:
        clasificacion = clasificar_ip(ip)
        if clasificacion:
            cursor.execute('''
                INSERT OR IGNORE INTO ips (ip, vlan, tipo, campus, tercer_octeto)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip,
                clasificacion['vlan'],
                clasificacion['tipo'],
                clasificacion['campus'],
                clasificacion['tercer_octeto']
            ))
    conn.commit()
    conn.close()

def obtener_vlans_disponibles():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''SELECT DISTINCT vlan, tipo FROM ips ORDER BY tipo, vlan''')
    resultados = cursor.fetchall()
    conn.close()
    return resultados

def filtrar_ips_por_vlan_tipo(vlan, tipo):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if tipo == 'Ambos':
        cursor.execute('SELECT ip FROM ips WHERE vlan = ?', (vlan,))
    else:
        cursor.execute('SELECT ip FROM ips WHERE vlan = ? AND tipo = ?', (vlan, tipo))
    resultados = [row[0] for row in cursor.fetchall()]
    conn.close()
    return resultados
