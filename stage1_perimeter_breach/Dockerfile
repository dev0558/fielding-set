FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create FortiManager-like filesystem
RUN mkdir -p /var/fmg/data/device_configs
RUN mkdir -p /var/fmg/data/backups
RUN mkdir -p /var/fmg/data/logs
RUN mkdir -p /var/fmg/tmp/.tm

# Place the flag inside a realistic-looking FortiGate config export
# Hidden in /var/fmg/tmp/.tm/ (same staging path real UNC5820 attackers used)
RUN printf '# \n# FortiGate Configuration Export\n# Exported by: FMG-SANDSTORM-01 via FGFM\n# Date: 2024-10-14 03:14:30 UTC\n# Device: FGT-GW-CORE-01 (10.50.1.100)\n#\n\nconfig system global\n    set hostname "FGT-GW-CORE-01"\n    set timezone 04\nend\n\nconfig system interface\n    edit "port1"\n        set ip 10.50.1.100 255.255.255.0\n        set allowaccess ping https ssh snmp fgfm\n    next\n    edit "port2"\n        set ip 10.50.2.1 255.255.255.0\n        set allowaccess ping https\n    next\nend\n\nconfig system admin\n    edit "admin"\n        set accprofile "super_admin"\n        set password ENC SH2yJDUkcm91bmRzPTUwMDA\n    next\n    edit "ir_analyst"\n        set accprofile "read_only"\n        set vdom "root"\n        set ir-response-key t4um4t4wh4k4t4ng1h4ng4\n    next\nend\n\nconfig firewall policy\n    edit 1\n        set name "LAN-to-WAN"\n        set srcintf "port2"\n        set dstintf "port1"\n        set action accept\n    next\nend\n' > /var/fmg/tmp/.tm/fgt_config_export.conf

# Decoy device configs (visible, interesting but no flag)
RUN echo '{"hostname":"FGT-GW-CORE-01","model":"FortiGate-600E","firmware":"7.2.8","mgmt_ip":"10.50.1.100","ha_status":"active"}' > /var/fmg/data/device_configs/FGT-GW-CORE-01.json
RUN echo '{"hostname":"FGT-DMZ-FW-02","model":"FortiGate-400F","firmware":"7.4.1","mgmt_ip":"10.50.1.101","ha_status":"standalone"}' > /var/fmg/data/device_configs/FGT-DMZ-FW-02.json
RUN echo '{"hostname":"FGT-BRANCH-03","model":"FortiGate-80F","firmware":"7.2.5","mgmt_ip":"10.50.1.102","ha_status":"standalone"}' > /var/fmg/data/device_configs/FGT-BRANCH-03.json

# Decoy backup file (red herring)
RUN echo "encrypted_backup_placeholder" > /var/fmg/data/backups/fmg_backup_20241015.bak

# Decoy audit log
RUN printf '[2024-10-14 02:30:11] FGFM: Device FGT-GW-CORE-01 heartbeat received\n[2024-10-14 02:30:12] FGFM: Device FGT-DMZ-FW-02 heartbeat received\n[2024-10-14 02:30:13] FGFM: Device FGT-BRANCH-03 heartbeat received\n[2024-10-14 03:14:22] FGFM: WARNING - Unregistered device connection from 45.32.41.202\n[2024-10-14 03:14:23] FGFM: JSON-RPC exec call processed - no auth check performed\n' > /var/fmg/data/logs/fgfm_audit.log

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
