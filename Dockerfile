FROM ubuntu:14.04

RUN apt-get update && apt-get install python-virtualenv python-yaml

RUN virtualenv --system-site-packages /janitor
ADD . /janitor
RUN /janitor/bin/pip install -r /janitor/requirements.txt

CMD /janitor/bin/cloud-janitor