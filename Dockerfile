FROM dockyardprod.kdc.capitalone.com/cloudmaid/python:2-alpine

ADD . /src
WORKDIR /src
RUN pip install -r requirements.txt
RUN python setup.py develop

VOLUME ["/var/log/cloud-maid", "/etc/cloud-maid"]

ENTRYPOINT ["/usr/local/bin/cloud-maid"]
