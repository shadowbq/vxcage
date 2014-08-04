from invoke import run, task

@task
def clean(docs=False, bytecode=True, extra=''):
    patterns = ['build']
    if docs:
        patterns.append('docs/_build')
    if bytecode:
        patterns.append('**/*.pyc')
    if extra:
        patterns.append(extra)
    for pattern in patterns:
        print ("rm -rf %s" % pattern)
        run("rm -rf %s" % pattern)

@task
def webserver(docs=False):
    run("cd vxcage && python api.py")
    if docs:
        run("sphinx-build docs docs/_build")
