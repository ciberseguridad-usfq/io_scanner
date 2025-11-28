import sqlite3
from collections import defaultdict

# Crear base de datos en memoria
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()

# Crear tabla para almacenar las IPs clasificadas
cursor.execute('''
CREATE TABLE ips (
    ip TEXT PRIMARY KEY,
    vlan INTEGER,
    tipo TEXT,
    campus TEXT
)
''')

# Diccionario temporal para agrupar IPs por VLAN
vlans = defaultdict(list)

# Procesar el archivo ips.txt
with open('ips.txt', 'r') as file:
    for line in file:
        ip = line.strip()
        if not ip:
            continue
        
        octetos = ip.split('.')
        
        # Clasificar por tipo de red
        if ip.startswith('172.'):
            tipo = "Campus"
            campus = "Cumbayá"
            vlan_id = int(octetos[2])  # Tercer octeto = VLAN
        elif ip.startswith('10.'):
            tipo = "Externo"
            campus = "Externo"
            vlan_id = int(octetos[2])  # Tercer octeto = VLAN
        else:
            continue  # Saltar otras redes no especificadas
        
        # Guardar en la base de datos
        cursor.execute('''
        INSERT INTO ips (ip, vlan, tipo, campus)
        VALUES (?, ?, ?, ?)
        ''', (ip, vlan_id, tipo, campus))
        
        # Agregar a la estructura de agrupación
        vlans[(tipo, vlan_id)].append(ip)

# Guardar cambios
conn.commit()

# Ejemplo de consulta: Mostrar distribución de VLANs
print("Resumen de VLANs:")
cursor.execute('''
SELECT vlan, tipo, campus, COUNT(*) as cantidad
FROM ips
GROUP BY vlan, tipo
ORDER BY tipo, vlan
''')

for row in cursor.fetchall():
    print(f"VLAN {row[0]} ({row[2]}): {row[3]} IPs")

# Cerrar conexión cuando ya no se necesite
# conn.close()