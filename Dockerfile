FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# mysqlclient necesita headers de MySQL/MariaDB y un compilador para construirse.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8000

# Toda la configuración (SECRET_KEY, DB, Wazuh, Gemini) se pasa por variables de
# entorno en tiempo de ejecución (docker run --env-file .env / docker-compose),
# nunca se hornea en la imagen. Ver .env.example para las variables requeridas.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["gunicorn", "sentria_project.wsgi:application", "--bind", "0.0.0.0:8000"]
