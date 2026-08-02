"""Single source of truth for the version this build reports.

server.py used to resolve its wire version from INSTALLED DIST METADATA. On a
box whose source tree is updated in place over a venv still holding the older
wheel, that reports the old version while running the new code, which is the
one situation where an operator most needs the number to be right. A literal
in the tree cannot drift from the tree.

Three consumers read it: __init__.__version__, the serverInfo version on the
wire, and the outbound User-Agent (which sat at a hand-written "0.2" through
two releases). pyproject.toml and server.json cannot import Python, so a test
asserts all of them agree rather than trusting the next bump to touch every
file.
"""

SERVER_VERSION = "0.3.1"
