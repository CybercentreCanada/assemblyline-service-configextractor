#!/bin/bash
python3.9 -m venv $1/venv
. $1/venv/bin/activate
pip install -U pip
# Configure global proxy for pip
if [ -n "$PIP_PROXY" ]; then pip config set global.proxy $PIP_PROXY; fi
pip install -r $1/requirements.txt --no-deps
