FROM python:3
ENV PYTHONUNBUFFERED=1
WORKDIR /authuser
COPY requirements.txt /authuser/
RUN apt-get update && \
    apt-get install -y nano && \
    pip install -r requirements.txt
COPY . /authuser/
