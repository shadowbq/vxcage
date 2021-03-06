import importlib
import os
from vxcage.lib.objects import Config
from invoke import run, task

@task
def clean(docs=False, bytecode=True, extra=''):
    """ Clean up docs, bytecode, and extras """
    patterns = ['build']
    if docs:
        patterns.append('docs/_build')
    if bytecode:
        patterns.append('**/*.pyc')
        patterns.append('./*.pyc')
    if extra:
        patterns.append(extra)
    for pattern in patterns:
        print ("Clearing rm -rf %s" % pattern)
        run("rm -rf %s" % pattern)

@task
def clobber(post=[clean], datastore=True, db=True):
    """ Delete malware store, Truncate database, Delete docs, bytecode, and extras """
    patterns = []
    if datastore:
        patterns.append(Config().api.repository)
    if db:
        print _truncate_db()
    for pattern in patterns:
        print ("Clearing rm -rf %s" % pattern)
        run("rm -rf %s" % pattern)

@task
def webserver(docs=False):
    """ Run the bottle.py test webapp on http://0.0.0.0:8080 """
    run("cd vxcage && python api.py -H 0.0.0.0")
    if docs:
        run("sphinx-build docs docs/_build")

@task
def rest_client(docs=False):
    """ Run the cli REST API client application """
    run("cd bin && python vxcage.py")


@task 
def truncate():
    """ Truncate the Database only """
    print _truncate_db()

def _truncate_db():
    from vxcage.lib.database import Database

    db = Database()
    
    if db.truncate():
        return "Completed truncation"
    else:
        return "Failed to Truncate"
