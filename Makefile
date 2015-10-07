
install:
	virtualenv .
	source bin/activate && pip install -r requirements.txt


coverage:
	./bin/nosetests -s -v --with-coverage --cover-html --cover-package=janitor --cover-html-dir=cover janitor
