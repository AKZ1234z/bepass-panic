#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if ! python3 -c "import flask" 2>/dev/null; then
    pip3 install -r requirements.txt
fi

python3 app.py
