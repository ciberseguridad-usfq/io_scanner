FROM python:3.11

# Instalar nmap y dependencias optimizadas
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        sqlite3 \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Exponer puerto (aunque uses host network)
EXPOSE 5000

CMD ["python", "app.py"]