all: validate dump unittests

validate:
	xmllint --relaxng firehose.rng --noout examples/example-*.xml

dump:
	python firehose/firehose.py

unittests:
	python -m unittest discover -v
