FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create file system structure mimicking FortiManager
RUN mkdir -p /var/fmg/data/device_configs/.archive /var/fmg/data/certs /etc/fmg

# Split the encryption key across two files
RUN echo -n "s4ndst0rm_t3l3c0m_" > /etc/fmg/.fgfm_psk
RUN echo -n "k3y_2024_f0rt1jump!" > /var/fmg/data/certs/ca_passphrase.txt

# Generate encrypted flag file at build time
RUN echo -n "INCIDENT_TOKEN_FRAGMENT_1=t4um4t4wh4k4t4ng1h4ng4" | openssl enc -aes-256-cbc -salt -pbkdf2 -k "s4ndst0rm_t3l3c0m_k3y_2024_f0rt1jump!" -out /var/fmg/data/device_configs/.archive/incident_token.enc

# Plant realistic decoy files in the config directory
RUN echo '{"hostname":"FGT-GW-CORE-01","model":"FortiGate-600E","firmware":"7.2.8"}' > /var/fmg/data/device_configs/FGT-GW-CORE-01.json
RUN echo '{"hostname":"FGT-DMZ-FW-02","model":"FortiGate-400F","firmware":"7.4.1"}' > /var/fmg/data/device_configs/FGT-DMZ-FW-02.json
RUN echo '{"hostname":"FGT-BRANCH-03","model":"FortiGate-80F","firmware":"7.2.5"}' > /var/fmg/data/device_configs/FGT-BRANCH-03.json

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
