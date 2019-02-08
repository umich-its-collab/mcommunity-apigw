import os
import subprocess

import pytest

pytest_plugins = "pep8"


@pytest.fixture(scope="session")
def mock_mcomm():
    p = subprocess.Popen(['python3', os.path.join(os.path.dirname(__file__), 'mock_mcomm.py')])
    yield p
    p.kill()
