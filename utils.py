# -*- coding: utf-8 -*-

import os
import logging
import json
import string

from objects import File, Config

logging.basicConfig(
    format="%(levelname) -10s %(asctime)s %(message)s",
    level=logging.DEBUG
)

def jsonize(data):
    logging.debug('json:' + json.dumps(data))
    return json.dumps(data, sort_keys=False, indent=4)

def store_sample(data):
    sha256 = File(file_data=data).get_sha256()
    
    folder = os.path.join(Config().api.repository, sha256[0], sha256[1], sha256[2], sha256[3])
    if not os.path.exists(folder):
        os.makedirs(folder, 0750)

    file_path = os.path.join(folder, sha256)

    if not os.path.exists(file_path):
        sample = open(file_path, "wb")
        sample.write(data)
        sample.close()
    
    return file_path

def get_sample_path(sha256):
    path = os.path.join(Config().api.repository, sha256[0], sha256[1], sha256[2], sha256[3], sha256)
    if not os.path.exists(path):
        return None
    return path






