#!/bin/bash
set -euo pipefail

# Always use this checkout, even when an old venv or another folder is active.
cd "$(dirname "$0")"
if [[ ! -f app.py || ! -f requirements-browser.txt ]]; then
  echo 'Неполная копия проекта. Выполните git pull --ff-only в ~/StoreLens.' >&2
  exit 1
fi

PYTHON_BASE="$(python3 -c 'import sys; print(getattr(sys, "_base_executable", sys.executable))')"
"$PYTHON_BASE" -c 'import sys; assert sys.version_info >= (3, 11), "Нужен Python 3.11 или новее"'

if [[ ! -e .venv-browser ]]; then
  "$PYTHON_BASE" -m venv .venv-browser
fi
if [[ ! -x .venv-browser/bin/python ]]; then
  echo 'Папка .venv-browser существует, но в ней нет Python. Сохраните или переименуйте её и повторите запуск.' >&2
  exit 1
fi

VENV_PYTHON="$PWD/.venv-browser/bin/python"
"$VENV_PYTHON" -c 'import pathlib,sys; assert pathlib.Path(sys.prefix).resolve() == pathlib.Path.cwd() / ".venv-browser", "Окружение относится к другой папке"'
"$VENV_PYTHON" -m pip install -r requirements-browser.txt
"$VENV_PYTHON" -m playwright install chromium

# app.py verifies an actual browser launch before opening the web server.
exec "$VENV_PYTHON" app.py --browser --port "${STORELENS_PORT:-8001}"
