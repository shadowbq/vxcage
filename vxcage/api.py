#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import json
import requests
import logging
import pefile
import zipfile
import tempfile

try:
    from bottle import route, request, response, run, server_names, ServerAdapter, hook, HTTPError
except ImportError:
    sys.exit("ERROR: Bottle.py library is missing")

from lib.objects import File, Config
from lib.database import Database
from lib.utils import jsonize, store_sample, store_secure_sample, get_sample_path

# VxCage External Libraries 

try:
    from ext import peutils
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError as e:
    print e
    sys.exit("ERROR: 'PEFile & PEUtils' VxCage EXT library failed to load")


try:
    from ext.pdfid import PDFiD2JSON, PDFiD
except MemoryError:
    logging.exception("Out of memory")
    sys.exit("Out of memory error")
except ImportError:
    sys.exit("ERROR: 'PDFiD' VxCage EXT library failed to load")

#-----------------------------------------------------------------------------
# Code
#-----------------------------------------------------------------------------


@route("/about", method="GET")
def about():
    return jsonize({"version": "1.4.0", "source": "https://github.com/shadowbq/vxcage", "zip-password": Config().api.zip_password})

@route("/test", method="GET")
def test():
    return jsonize({"message" : "test"})

@route("/malware/add", method="POST")
def add_malware():
    try:
        tags = request.forms.get("tags")
        
        #data is a Bottle FileUpload obj
        data = request.files.file
        
        info = File(file_path=store_sample(data.file.read()))

        db.add(obj=info, file_name=data.filename, tags=tags)

        response.content_type = 'application/json'
        return jsonize({"message" : "added"})

    except MemoryError:
        logging.exception("Out of memory")
        sys.exit("Out of memory error")
    except RuntimeError:
        response.content_type = 'application/json'
        response.status = 504
        return jsonize({"error" : "timeout"})

#Store malware via a submission in a ZIP file(one file per) with a password
@route("/malware/secure/add", method="POST")
def add_secure_malware():
    try:
        tags = request.forms.get("tags")
        password = request.forms.get("password")
        if password is None:
            zpwd = Config().api.zip_password
            if zpwd is None:
                logging.debug ("No ZIP password")
            else:
                logging.debug ("Using default ZIP password: '" + zpwd + "'")
                password = zpwd
        else:
            logging.debug ("Request ZIP password: '" + password + "'")

        #data is a Bottle FileUpload obj
        data = request.files.file
        
        #store_secure_sample(data.file.read(), "infected")
        info = File(file_path=store_secure_sample(data.file.read(), password))
        db.add(obj=info, file_name=data.filename, tags=tags)

        response.content_type = 'application/json'
        return jsonize({"message" : "added"})

    except MemoryError:
        logging.exception("Out of memory")
        sys.exit("Out of memory error")
    except RuntimeError:
        response.content_type = 'application/json'
        response.status = 504
        return jsonize({"error" : "timeout"})

# Return the Binary data of the file hash requested
# "GET /malware/get/8d7e9d9bc527dcc05ec40ab9d4f48091d27ba384ff966bf299e4bc20899bcfe1 HTTP/1.1" 200 169966
@route("/malware/get/<filehash>", method="GET")
def get_malware(filehash):
    logging.debug("@route(/malware/get/<filehash>")
    
    if filehash:
        result = _find_lazy_hash(filehash) #db.find_sha256(filehash)
        
        if result :
                sha256 = result.sha256
                logging.debug("DB entry found.")
                path = get_sample_path(sha256)
        
                if not path:
                    logging.exception("DB entry with Path NOT found: " + sha256)
                    response.content_type = 'application/json'
                    response.status = 404
                    return jsonize({"error" : "file_not_found"})
                else:
                    logging.debug("Returning Data.")
                    response.content_length = os.path.getsize(path)
                    response.content_type = "application/octet-stream; charset=UTF-8"
                    data = open(path, "rb").read()
                    return data

        else:
            logging.debug("DB entry NOT found.")
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})
    else:
        return jsonize({"error" : "Missing hash param"}) 

# Return the Binary data of the file hash requested in a password protected ZIP file.
#http://10.200.0.53:8080/malware/secure/get/8d7e9d9bc527dcc05ec40ab9d4f48091d27ba384ff966bf299e4bc20899bcfe1
@route("/malware/secure/get/<filehash>", method="GET")
def get_secure_malware(filehash):
    logging.debug("@route(/malware/secure2/get/<filehash>")
    
    try:
        import pyminizip
    except:
        "missing pyminizip library"
    
    if filehash:
        zpwd = Config().api.zip_password
        result = _find_lazy_hash(filehash) #db.find_sha256(filehash)
        
        if result :
            sha256 = result.sha256
            logging.debug("DB entry found.")
            path = get_sample_path(sha256)
    
            if not path:
                logging.exception("DB entry with Path NOT found: " + sha256)
                response.content_type = 'application/json'
                response.status = 404
                return jsonize({"error" : "file_not_found"})
            else:
                logging.debug("Returning Data.")
                tf = tempfile.NamedTemporaryFile(delete=False)
                zipFileName = tf.name
                tf.close()
                
                compression_level = 5
                pyminizip.compress(path, zipFileName, zpwd, compression_level)
                
                response.content_length = os.path.getsize(zipFileName)
                response.content_type = "application/octet-stream; charset=UTF-8"
                data = open(zipFileName, "rb").read()

                return data

        else:
            logging.debug("DB entry NOT found.")
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})
    else:
        return jsonize({"error" : "Missing hash param"})

# Server Search online for Malware
@route("/malware/scavenge/<filehash>", method="GET")
def get_scavenge(filehash):
    db = Database()
    md5 = None
    sha256 = filehash
    data = None
    
    try:
        ############
        # Malshare #
        ############
        logging.info("Downloading sample from MalShare")
        malshare_api_key = Config().malshare.api_key
        payload = { 'action'  : 'getfile',
                    'api_key' : malshare_api_key,
                    'md5'     : filehash }
        url = "http://api.malshare.com/sampleshare.php"
        user_agent = {'User-agent': 'wget_malshare daily 1.0'}
        r = requests.get(url, params=payload, headers=user_agent)
        data = r.content
        if data != "Sample not found" and data != "Empty hash specified":
            tags = 'malshare'
            info = File(file_data=data)
            if db.add(file_obj=info, file_name="malshare_" + filehash, file_data=data, tags=tags):
                logging.info("Added sample from malshare")
            else:
                logging.info("Failed to add sample from malshare")
        else:
            data = None
    except Exception:
        logging.exception("Something went wrong while download from Malshare")
        pass

    if not data:
        # Not in local repository. Let's see if anyone else has it.
        try:
            ##############
            # Malware.lu #
            ##############
            logging.info("Downloading sample from malware.lu")
            malwarelu_api_key = Config().malwarelu.api_key
            url = "https://www.malware.lu/api/download"
            payload = { 'hash'   : filehash,
                        'apikey' : malwarelu_api_key }
            r = requests.post(url, data=payload)
            if r.headers['content-type'] == 'application/octet-stream':
                data = r.content
                tags = 'malwarelu'
                info = File(file_data=data)
                if db.add(file_obj=info, file_name="malwarelu_" + filehash, file_data=data, tags=tags):
                    logging.info("Added sample from malware.lu")
                else:
                    logging.info("Failed to add sample from malware.lu")
            else:
                data = None
        except Exception:
            logging.exception("Something went wrong while download from malware.lu")
            pass

    if not data:
        response.content_type = 'application/json'
        response.status = 404
        return jsonize({"error" : "file_not_found"})

    else:
        response.content_type = 'application/octet-stream'
        return data

@route("/malware/find/<filehash>", method="GET")
def find_malware_lazy():
    #Generic GET
    filehash = request.forms.get("filehash")

    if filehash:
        result = _find_lazy_hash(filehash)
        if result:
            response.content_type = 'application/json'
            return jsonize(_details(result))
        else:
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})

# Form based POST of explict Hash / Tag search to return hash match results.
@route("/malware/find", method="POST")
def find_malware():

    md5 = request.forms.get("md5")
    sha256 = request.forms.get("sha256")
    ssdeep = request.forms.get("ssdeep")
    imphash = request.forms.get("imphash")
    tag = request.forms.get("tag")
    date = request.forms.get("date")

    if md5:
        row = db.find_md5(md5)
        if row:
            response.content_type = 'application/json'
            return jsonize(_details(row))
        else:
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})
    elif sha256:
        row = db.find_sha256(sha256)
        if row:
            response.content_type = 'application/json'
            return jsonize(_details(row))
        else:
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})
    else:
        if ssdeep:
            rows = db.find_ssdeep(ssdeep)
        if imphash:
            rows = db.find_imphash(imphash)
        elif tag:
            rows = db.find_tag(tag)
        elif date:
            rows = db.find_date(date)
        else:
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "invalid_search_term"})

        if not rows:
            response.content_type = 'application/json'
            response.status = 404
            return jsonize({"error" : "file_not_found"})

        results = []
        for row in rows:
            entry = _details(row)
            results.append(entry)

        response.content_type = 'application/json'
        return jsonize(results)

@route("/tags/list", method="GET")
def list_tags():
    rows = db.list_tags()

    results = []
    for row in rows:
        results.append(row.tag)

    response.content_type = 'application/json'
    response.status = 404
    return jsonize(results)

@route("/vt/error", method="GET")
def vt_error():
    rows = db.vt_error()

    results = []
    for row in rows:
        results.append(row.sha256)
    
    response.content_type = 'application/json'
    return jsonize(results)

@route("/vt/missing", method="GET")
def vt_missing():
    rows = db.vt_missing()

    results = []
    for row in rows:
        results.append(row.sha256)

    response.content_type = 'application/json'
    return jsonize(results)

@route("/malware/total", method="GET")
def total_samples():
    results = db.total_samples()

    response.content_type = 'application/json'
    return jsonize(results)


def _find_lazy_hash(filehash):
    if len(filehash) == 32:
        logging.debug("Most likely we got a MD5 checksum, do a lookup...")
        try:
            result = db.find_md5(filehash)
        except Exception:
            logging.exception("MD5 Sample not found")
            pass

    if len(filehash) == 40:
        logging.debug("Most likely we got a SHA1 checksum, do a lookup...")
        try:
            result = db.find_sha1(filehash)
        except Exception:
            logging.exception("SHA1 Sample not found")
            pass

    if len(filehash) == 64:
        logging.debug("Most likely we got a SHA256 checksum, do a lookup...")
        try:
            result = db.find_sha256(filehash)
        except Exception:
            logging.exception("SHA256 Sample not found")
            pass

    if len(filehash) == 128:
        logging.debug("Most likely we got a SHA512 checksum, do a lookup...")
        try:
            result = db.find_sha512(filehash)
        except Exception:
            logging.exception("SHA512 Sample not found")
            pass
            
    return result

def _details(row):
    tags = []
    for tag in row.tag:
        tags.append(tag.tag)

    entry = {
        "id" : row.id,
        "file_name" : row.file_name,
        "file_type" : row.file_type,
        "file_size" : row.file_size,
        "md5" : row.md5,
        "sha1" : row.sha1,
        "sha256" : row.sha256,
        "sha512" : row.sha512,
        "crc32" : row.crc32,
        "ssdeep": row.ssdeep,
        "imphash": row.imphash,
        "exif": row.exif,
        "virustotal": row.virustotal,
        "peid": row.peid,
        "pdfid": row.pdfid,
        "created_at": row.created_at.__str__(),
        "tags" : tags
    }

    return entry

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the API server on", default="localhost", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the API server on", default=8080, action="store", required=False)
    args = parser.parse_args()


    db = Database()
    logging.debug("Launching bottle route paths in Main")
    run(host=args.host, port=args.port)

