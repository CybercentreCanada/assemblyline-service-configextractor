#!/bin/bash
python3.9 -m venv $1/venv
. $1/venv/bin/activate
pip install -U pip
pip install -r $1/requirements.txt --no-deps
