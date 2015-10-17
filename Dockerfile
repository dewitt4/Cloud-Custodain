FROM pypy:2

RUN apt-get update && apt-get install -y python-virtualenv

ADD . /janitor
RUN virtualenv -p /usr/local/bin/pypy /janitor
RUN /janitor/bin/pip install -r /janitor/requirements.txt

VOLUME ["/var/log/cloud-maid", "/etc/cloud-maid"]

ENTRYPOINT ["/janitor/bin/cloud-maid"]
