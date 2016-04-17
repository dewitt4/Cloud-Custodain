FROM dockyardprod.kdc.capitalone.com/cloudmaid/python:2-alpine

ADD . /src
WORKDIR /src
RUN pip install -r requirements.txt
RUN python setup.py develop

VOLUME ["/var/log/cloud-custodian", "/etc/cloud-custodian"]

ENTRYPOINT ["/usr/local/bin/custodian"]
