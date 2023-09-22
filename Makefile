dev:
		pip install -r requirements.txt
		pip install -e ./

build:
		python3 -m build

docs:
		mkdocs build -d public

.PHONY: dev build docs