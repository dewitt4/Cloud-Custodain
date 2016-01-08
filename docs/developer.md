# Developer Install


## Requirements

- Ensure proxy is configured properly

### On Linux

```bash
sudo apt-get install python python-dev python-pip python-virtualdev
```

### On Mac

```bash
brew install python
```

## Installing

First, clone the repository:

```bash
$ git clone https://github.kdc.capitalone.com/cloud-maid/cloud-maid.git
```

Also recommended is to use a virtualenv to sandbox this install from your system packages:

```bash
$ virtualenv cloud-maid
$ source cloud-maid/bin/activate
```

And then install the dependencies. Deployed systems will just use `requirements.txt`; you'll need the additional testing libraries in `requirements-dev.txt`.

```bash
$ pip install -r requirements-dev.txt
```

And then the maid itself

```bash
$ python setup.py develop
```

You should have the cloud-maid command available now.

```bash
$ cloud-maid -h
```

## Running tests

There are several additional dependencies for running unit tests.

```bash
$ cd cloud-maid
$ source bin/activate
$ pip install nosetests
$ pip install mock
```

And then unit tests can be run with

```bash
$ make tests
```

