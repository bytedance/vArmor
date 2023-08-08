FROM python:3.10-slim-buster

WORKDIR /home/varmor

COPY cmd/classifier/app ./app
COPY cmd/classifier/boot.sh ./boot.sh
COPY cmd/classifier/wsgi.py ./wsgi.py

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/adobe/stringlifier.git

COPY cmd/classifier/requirements.txt ./stringlifier/requirements.txt
WORKDIR /home/varmor/stringlifier
RUN pip3 install torch==1.13.1 --extra-index-url https://download.pytorch.org/whl/cpu;
RUN python3 setup.py install

WORKDIR /home/varmor

USER 10001

EXPOSE 5000
ENTRYPOINT ["./boot.sh"]
