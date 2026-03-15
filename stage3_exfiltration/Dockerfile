FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir scapy

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python generate_pcap.py
RUN mkdir -p /app/artifacts
RUN mv c2_capture.pcapng /app/artifacts/

EXPOSE 80

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
