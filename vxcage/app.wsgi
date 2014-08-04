import os
import sys

cur_dir = os.path.dirname(__file__)

os.chdir(cur_dir)
sys.path.append(cur_dir)

import bottle
import api

application = bottle.default_app()
