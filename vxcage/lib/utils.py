# -*- coding: utf-8 -*-

import os
import logging
import json
import string
import zipfile
import tempfile
import sys

from .objects import File, Config

#-----------------------------------------------------------------------------
# Code
#-----------------------------------------------------------------------------

logging.basicConfig(
    format="%(levelname) -10s %(asctime)s %(message)s",
    level=logging.DEBUG
)

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

def jsonize(data):
    logging.debug('json:' + json.dumps(data))
    return json.dumps(data, sort_keys=False, indent=4)

def store_sample(data):
    sha256 = File(file_data=data).get_sha256()
    
    logging.debug("SHA256 of store submission: " + sha256)

    folder = os.path.join(Config().api.repository, sha256[0], sha256[1], sha256[2], sha256[3])
    if not os.path.exists(folder):
        os.makedirs(folder, 0750)

    file_path = os.path.join(folder, sha256)

    if not os.path.exists(file_path):
        sample = open(file_path, "wb")
        sample.write(data)
        sample.close()
    
    return file_path


def store_secure_sample(data, password = None):
    zsha256 = File(file_data=data).get_sha256()
    logging.debug("SHA256 of store zip submission: " + zsha256)

    tf = tempfile.NamedTemporaryFile(delete=False)
    logging.debug("Writing to tmp: " + tf.name)

    #store zip to disk
    tf.write(data)
    tf.flush()
    tf.close

    logging.info(tf.name + " : " + str(zipfile.is_zipfile(tf.name)))

    try:
        zipped = zipfile.ZipFile(tf.name, 'r')
        if password is None:
            infectedfile = zipped.open(zipped.infolist()[0], 'r')
        else:
            infectedfile = zipped.open(zipped.infolist()[0], 'r', C2BIP3(password))
        
    except:
        print('Error opening file %s' % file)
        print(sys.exc_info()[1])
        sys.exit()

    
    
    try:
        uzdata = infectedfile.read()
        
    
        sha256 = File(file_data=uzdata).get_sha256()
        logging.debug("SHA256 of unzip submission: " + sha256)

    
        folder = os.path.join(Config().api.repository, sha256[0], sha256[1], sha256[2], sha256[3])
        if not os.path.exists(folder):
            os.makedirs(folder, 0750)

        file_path = os.path.join(folder, sha256)

        if not os.path.exists(file_path):
            sample = open(file_path, "wb")
            sample.write(uzdata)
            sample.close()
        
        infectedfile.close()

    finally:
        logging.debug("Closing ZIP file")
        zipped.close()

    return file_path


def get_sample_path(sha256):
    path = os.path.join(Config().api.repository, sha256[0], sha256[1], sha256[2], sha256[3], sha256)
    logging.debug("Searching path: " + path)
    if not os.path.exists(path):
        return None
    return path






