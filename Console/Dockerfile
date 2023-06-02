FROM ubuntu:20.04

RUN mkdir /server_db

COPY . /server_db

RUN apt -y update && apt -y upgrade

WORKDIR /server_db

RUN apt-get install python3-pip -y

RUN python3 -m pip install -r requirements.txt

EXPOSE 9999

CMD ["python3","-u", "server.py"]