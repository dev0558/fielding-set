FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate encrypted flag file at build time
RUN mkdir -p /opt/panlogs/restricted/incident /opt/panlogs/tmp
RUN echo "s4ndst0rm_t3l3c0m_k3y_2024!" > /opt/panlogs/tmp/.syskey
RUN echo "INCIDENT_TOKEN_FRAGMENT_1=t4um4t4wh4k4t4ng1h4ng4" | openssl enc -aes-256-cbc -salt -pbkdf2 -k "s4ndst0rm_t3l3c0m_k3y_2024!" -out /opt/panlogs/restricted/incident/part1.enc

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
