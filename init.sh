#!/bin/bash

cd $(readlink -fn $(dirname "$BASH_SOURCE"))

if which virtualenv; then
    [[ -d venv/bin ]] || virtualenv -p python3 venv
    . venv/bin/activate
    pip install -U pip
    pip install -U -r requirements.txt
else
    echo "Automated environment setup requires virtualenv."
fi
