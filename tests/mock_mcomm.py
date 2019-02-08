#!/usr/bin/env python
import json
import os

from flask import Flask

app = Flask(__name__)


def get_testdata(base, name):
    fname = os.path.join(os.path.dirname(__file__), 'data/{}_{}.json'.format(base, name))
    if os.path.exists(fname):
        with open(fname, 'r') as f:
            return f.read()
    else:
        return '{}'


@app.route("/iamGroups/create", methods=['POST'])
@app.route("/iamGroups/delete/<dn>", methods=['GET'])
@app.route("/iamGroups/renew/<dn>", methods=['GET'])
@app.route("/iamGroups/reserve", methods=['POST'])
@app.route("/iamGroups/update/<attrib>", methods=['POST'])
def return_success(attrib=False, dn=False):
    return '{"status": "success"}'


@app.route("/iamGroups/profile/dn/<dn>", methods=['GET'])
def get_group(dn):
    cn = dn.split(',')[0].split('=')[1]
    return get_testdata('profile', cn)


@app.route("/iamGroups/find/both/<name>", methods=['GET'])
def get_both(name):
    return get_testdata('find_both', name)


@app.route("/iamGroups/find/person/<uid>", methods=['GET'])
def get_user(uid):
    return get_testdata('find_person', uid)


@app.route("/iamGroups/isValidName/<name>", methods=['GET'])
def is_valid_name(name):
    if name != 'badname':
        return '{"valid": "true"}'
    else:
        return '{"valid": "false"}'


@app.route("/inst/oauth2/token", methods=['POST'])
def return_token():
    return '{"access_token": "a1b2c3d4c5d6e7f8g9h10i11j12k13l14"}'


def main():
    app.run()

if __name__ == '__main__':
    main()
