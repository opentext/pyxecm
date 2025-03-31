install:
		brew install uv
		uv sync --locked --extra dataloader --extra profiling --extra browserautomation

build:
		uv build

docs:
		uv run settings-doc generate --class pyxecm.customizer.settings.Settings --output-format markdown --heading-offset 1 > customizersettings_doc.md
		uv run settings-doc generate --class pyxecm.customizer.settings.Settings --output-format dotenv > customizersettings.env
		uv run settings-doc generate --class pyxecm.customizer.api.settings.CustomizerAPISettings --output-format markdown --heading-offset 1 > customizerapisettings_doc.md
		uv run settings-doc generate --class pyxecm.customizer.api.settings.CustomizerAPISettings --output-format dotenv > customizerapisettings.env
		uv run mkdocs build -d public

ruff:
		uv run ruff format pyxecm
		uv run ruff check pyxecm --ignore FIX

.PHONY: install build docs