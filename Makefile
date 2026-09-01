.PHONY: check run
check:
	PYTHONPATH=src python -m unittest discover -s tests -v
	PYTHONPATH=src python -m compileall -q src

run:
	PYTHONPATH=src OSINT_TOOLS_DATA_DIR=./data python -m osint_tools.server
