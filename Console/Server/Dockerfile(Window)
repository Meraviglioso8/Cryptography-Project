FROM python:3.10.9

WORKDIR /server_db

COPY . /server_db

RUN pip install --upgrade pip

RUN pip install -r requirements.txt

EXPOSE 2525

CMD ["python", "-u", "server.py"]
