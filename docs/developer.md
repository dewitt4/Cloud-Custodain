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

And then install the dependencies

```bash
$ pip install -r requirements.txt
```

And then the maid itself

```bash
$ python setup.py develop
```

You should have the cloud-maid command available now.

```bash
$ cloud-maid -h
```


