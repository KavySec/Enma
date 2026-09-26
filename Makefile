install:
	pip install -e .

scan:
	python3 -m enma.cli scan example.com

diff:
	python3 -m enma.cli diff scan1.json scan2.json