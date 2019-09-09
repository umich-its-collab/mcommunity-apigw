import json
import os
import pytest
from unittest import mock
from mcommunity import MCommClient


data_dir = os.path.join(os.path.dirname(__file__) + '/data/')


@pytest.fixture
def mcclient():
    def _loader(filenames):
        for fname in filenames:
            with open(data_dir + fname, 'r') as f:
                data = json.load(f)
            yield data

    @mock.patch('mcommunity.mcommunity.MCommSession')
    def _client(json_files, session):
        session.return_value.get.return_value.json.side_effect = _loader(
            json_files
        )
        session.return_value.token = '12345'
        client = MCommClient(client_id='12345', secret='abdce')
        return client

    return _client


def test_group_fetch(mcclient):
    response_files = [
        'find_both_testgroup.json',
        'profile_testgroup.json'
    ]
    group = mcclient(response_files).group('testgroup')
    assert group.dn


def test_group_fetch_by_cn(mcclient):
    response_files = [
        'find_both_alias1.json',
        'profile_testgroup.json',
        'profile_testgroup.json'
    ]
    group = mcclient(response_files).group('alias1')
    assert group.dn
