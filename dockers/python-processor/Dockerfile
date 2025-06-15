FROM python:3.12

RUN pip install --upgrade pip && pip install scapy nats-py cryptography
RUN echo "python main.py" >> /root/.bash_history

WORKDIR /code/python-processor