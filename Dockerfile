FROM pypy:2

RUN apt-get update && apt-get install -y python-virtualenv

ADD . /src
RUN virtualenv -p /usr/local/bin/pypy /janitor

WORKDIR /src
RUN /janitor/bin/pip install -r requirements.txt
RUN /janitor/bin/python setup.py develop

VOLUME ["/var/log/cloud-maid", "/etc/cloud-maid"]

ENTRYPOINT ["/janitor/bin/cloud-maid"]
