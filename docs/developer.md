# Developer Install



You'll need python-dev and python-virtualenv packages installed already on linux, on
OSX the default install comes with the nesc requirements.

First clone the repository:

```bash
$ git clone https://github.kdc.capitalone.com/cloud-maid/cloud-maid.git
```

Also recommended is to use a virtualenv to sandbox this install from your system packages:

```bash
$ virtualenv cloud-maid
$ source cloud-maid/bin/activate
```

And then install the dependencies

```bash
$ pip install -f requirements.txt
```

And then the maid itself

```bash
$ python setup.py develop
```

You should have the cloud-maid command available now.

```bash
$ cloud-maid -h
```


