FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir scapy

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate Stage 1 encrypted flag
RUN mkdir -p /opt/panlogs/restricted/incident /opt/panlogs/tmp
RUN echo "s4ndst0rm_t3l3c0m_k3y_2024!" > /opt/panlogs/tmp/.syskey
RUN echo "INCIDENT_TOKEN_FRAGMENT_1=t4um4t4wh4k4t4ng1h4ng4" | openssl enc -aes-256-cbc -salt -pbkdf2 -k "s4ndst0rm_t3l3c0m_k3y_2024!" -out /opt/panlogs/restricted/incident/part1.enc
RUN echo "[2024-03-14 22:31:07] pan_task: backing up incident token to encrypted store" > /opt/panlogs/pan_task.log \
 && echo "[2024-03-14 22:31:07] pan_task: using syskey from /opt/panlogs/tmp/.syskey" >> /opt/panlogs/pan_task.log \
 && echo "[2024-03-14 22:31:08] pan_task: encrypted output written to /opt/panlogs/restricted/incident/part1.enc" >> /opt/panlogs/pan_task.log \
 && echo "[2024-03-14 22:31:08] pan_task: encryption method: openssl aes-256-cbc with pbkdf2" >> /opt/panlogs/pan_task.log

# Generate Stage 2 forensic artifacts
RUN python generate_artifacts.py
RUN mkdir -p /app/artifacts
RUN mv incident_dump.bin vss_snapshot.dd /app/artifacts/

# Generate Stage 3 PCAP
RUN python generate_pcap.py
RUN mv c2_capture.pcapng /app/artifacts/

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
