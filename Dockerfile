FROM python:2

ADD . /src
WORKDIR /src
RUN pip install -r requirements.txt
RUN python setup.py develop

VOLUME ["/var/log/cloud-maid", "/etc/cloud-maid"]

ENTRYPOINT ["/usr/local/bin/cloud-maid"]
