
import importlib
import logging

from ..vxcage.lib.database import Database

#-----------------------------------------------------------------------------
# Code
#-----------------------------------------------------------------------------


logging.basicConfig(
    format="%(levelname) -10s %(asctime)s %(message)s",
    level=logging.DEBUG
)

db = Database(cfg=['../etc/api.conf', '../tests/api.conf.test', os.path.expanduser('~/.vxcage.cfg')])
print "Truncating.."

if db.truncate():
	print "Completed truncation"
else:
	print "Failed to Truncate"
