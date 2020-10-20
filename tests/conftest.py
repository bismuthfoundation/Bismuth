# Replace python3 below with the binary matching your setup.
# For example: python (for venv), or python3.5, python3.6, etc
# python3 should work on most recent Linux distros

from os import chdir, environ
from subprocess import Popen
from time import sleep

import pytest

# Regnet on Legacy db
# REGNET_PARAM = "regnet"

# Regnet on V2 DB
REGNET_PARAM = "regnet2"

# Overload REGNET from ENV
ENV_REGNET = environ.get('REGNET')
if ENV_REGNET:
    REGNET_PARAM = ENV_REGNET

print(f"Using Regnet {REGNET_PARAM}")


@pytest.fixture(scope="session")
def myserver():
    chdir('..')
    p = Popen(["python3", "node.py", REGNET_PARAM])
    chdir('tests')
    # TODO: Since this time may be dependent on run and hardware,
    # have a way to know when the regnet node is up and ready instead of blind wait.
    sleep(10)  # Get some time for the node to boot up on slow machines
    yield
    p.terminate()
