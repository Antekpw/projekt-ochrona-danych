FROM python:3.12-slim

WORKDIR /app

ENV FLASK_APP=main.py
ENV FLASK_RUN_HOST=0.0.0.0
RUN apt-get update && apt-get install -y libmagic-dev
## moze build-essential jeszcze
COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

EXPOSE 5000
COPY . .

CMD ["flask","run","--debug"]