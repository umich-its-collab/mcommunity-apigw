#!/bin/bash
 
virtualenv -p python36 --system-site-packages bin/python
. bin/python/bin/activate
pip install -U pip
pip install -I -r python-requirements.txt
