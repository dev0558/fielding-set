FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create FortiManager-like filesystem
RUN mkdir -p /var/fmg/data/.incident_response
RUN mkdir -p /var/fmg/data/device_configs
RUN mkdir -p /var/fmg/data/backups
RUN mkdir -p /var/fmg/data/logs

# Place the flag (plaintext, in hidden directory)
RUN echo "INCIDENT_TOKEN_FRAGMENT_1=t4um4t4wh4k4t4ng1h4ng4" > /var/fmg/data/.incident_response/token_fragment_1.txt

# Decoy device configs
RUN echo '{"hostname":"FGT-GW-CORE-01","model":"FortiGate-600E","firmware":"7.2.8","mgmt_ip":"10.50.1.100","ha_status":"active"}' > /var/fmg/data/device_configs/FGT-GW-CORE-01.json
RUN echo '{"hostname":"FGT-DMZ-FW-02","model":"FortiGate-400F","firmware":"7.4.1","mgmt_ip":"10.50.1.101","ha_status":"standalone"}' > /var/fmg/data/device_configs/FGT-DMZ-FW-02.json
RUN echo '{"hostname":"FGT-BRANCH-03","model":"FortiGate-80F","firmware":"7.2.5","mgmt_ip":"10.50.1.102","ha_status":"standalone"}' > /var/fmg/data/device_configs/FGT-BRANCH-03.json

# Decoy backup file (red herring, not a real archive)
RUN echo "encrypted_backup_placeholder" > /var/fmg/data/backups/fmg_backup_20241015.tar.gz.enc

# Decoy audit log
RUN printf "[2024-10-14 02:30:11] FGFM: Device FGT-GW-CORE-01 heartbeat received\n[2024-10-14 02:30:12] FGFM: Device FGT-DMZ-FW-02 heartbeat received\n[2024-10-14 02:30:13] FGFM: Device FGT-BRANCH-03 heartbeat received\n[2024-10-14 03:14:22] FGFM: WARNING - Unregistered device connection from 45.32.41.202\n[2024-10-14 03:14:23] FGFM: JSON-RPC exec call processed - no auth check performed\n" > /var/fmg/data/logs/fgfm_audit.log

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
