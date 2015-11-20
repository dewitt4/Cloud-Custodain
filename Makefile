
install:
	virtualenv .
	source bin/activate && pip install -r requirements.txt
	source bin/activate && python setup.py develop

coverage:
	./bin/nosetests -s -v --with-coverage --cover-html --cover-package=janitor --cover-html-dir=cover janitor

tests:
	./bin/nosetests -s -v janitor

ftests:
	./bin/nosetests -s -v ftests

depcache:
	./bin/pip install -d deps -r requirements.txt
	tar cvf maid-deps.tgz deps

