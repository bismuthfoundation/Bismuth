# Replace python3 below with the binary matching your setup.
# For example: python (for venv), or python3.5, python3.6, etc
# python3 should work on most recent Linux distros

from os import chdir
import pytest
from subprocess import Popen
from time import sleep

@pytest.fixture(scope="session")
def myserver():
    chdir('..')
    p = Popen(["python3", "node.py", "regnet"])
    chdir('tests')
    sleep(12)
    yield
    p.terminate()
