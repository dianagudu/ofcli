import os

__version__ = "UNKNOWN"

with open(os.path.join(os.path.dirname(__file__), "VERSION")) as version_file:
    __version__ = version_file.read().strip()
