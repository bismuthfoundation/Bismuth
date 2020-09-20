# Replace python3 below with the binary matching your setup.
# For example: python (for venv), or python3.5, python3.6, etc
# python3 should work on most recent Linux distros

from os import chdir
from subprocess import Popen
from time import sleep

import pytest

# Regnet on Legacy db
# REGNET_PARAM = "regnet"

# Regnet on V2 DB
REGNET_PARAM = "regnet2"


@pytest.fixture(scope="session")
def myserver():
    chdir('..')
    p = Popen(["python3", "node.py", REGNET_PARAM])
    chdir('tests')
    sleep(5)  # Get some time for the node to boot up on slow machines
    yield
    p.terminate()
