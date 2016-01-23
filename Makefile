
install:
	virtualenv .
	source bin/activate && pip install -r requirements.txt
	source bin/activate && pip install -r tools/dev-requirements.txt
	source bin/activate && python setup.py develop

coverage:
	./bin/nosetests -s -v --with-coverage --cover-html --cover-package=janitor --cover-html-dir=cover janitor

tests:
	./bin/nosetests -s -v janitor

ftests:
	./bin/nosetests -s -v ftests

depcache:
	mkdir -p deps
	virtualenv dep-download
	dep-download/bin/pip install -d deps -r requirements.txt
	tar cvf maid-deps.tgz deps
	rm -Rf dep-download
	rm -Rf deps

sphinx:
	make -f docs/Makefile.sphinx clean && \
	make -f docs/Makefile.sphinx html

ghpages:
	git checkout gh-pages && \
	cp -r docs/build/html/* . && \
	git add -u && \
	git add _modules _sources _static generated *.html *.js && \
	git commit -m "Updated generated Sphinx documentation"
