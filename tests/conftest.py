import flask
import os
import pytest
import subprocess


@pytest.fixture(scope="session")
def mock_mcomm():
    os.environ["FLASK_APP"] = 'mock_mcomm.py'
    p = subprocess.Popen(['flask', 'run'])
    yield p
    p.kill()
