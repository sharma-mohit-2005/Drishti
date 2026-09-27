FROM ubuntu:18.04
RUN apt-get update && apt-get install -y openssl libssl1.1 python3-pip
RUN pip3 install pycryptodome==3.9.0
COPY . /opt/bharat
CMD ["/opt/bharat/start.sh"]
