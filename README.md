VxCage
======

VxCage is a WSGI Python application for managing a malware samples repository with a REST API interface.

Requirements
------------

In order to install VxCage you need to have Python (2.7) installed. Following are the required libraries.

* [bottle.py](http://www.bottlepy.org/) -- `pip install bottle`
* [sqlalchemy](http://www.sqlalchemy.org) -- `pip install sqlalchemy`


If you want to enable the fuzzy hash, you need to install.

* [ssdeep](http://ssdeep.sourceforge.net/) and the Python bindings, [pydeep](https://github.com/kbandla/pydeep).

On Ubuntu/Debian systems ``sudo apt-get install ssdeep libfuzzy-dev``

* [pydeep](http://ssdeep.sourceforge.net/) -- ``pip install pydeep``

In Development
----------

pyEXIFTool for inspecting Image files

* [pyEXIFTool](https://github.com/smarnach/pyexiftool) -- ``sudo pip install git+https://github.com/smarnach/pyexiftool.git#egg=pyexiftool``


Installation
------------

### PostgreSQL

First thing first, extract VxCage to your selected location and open `api.conf` and configure the path to the local folder you want to use as a storage.

This fork of VxCage *requires* PostgreSQL in order to take advantage of native json data types.

To install PostgreSQL requirements:

On Ubuntu/Debian systems ``apt-get install postgresql postgresql-contrib postgresql-server-dev-all libpq-dev``.


* [psycopg2](http://initd.org/psycopg/) PostgreSQL SQLAlchemy Bindings -- ``pip install psycopg2``

You also need to configure the connection string for your database in `api.conf`. For example:

PostgreSQL:

    postgresql://user:pass@host/database

Refer to [SQLAlchemy](http://docs.sqlalchemy.org/en/latest/core/engines.html)'s documentation for additional details.

### Apache Installation

If you plan to run VxCage with Apache, you'll need to have mod_wsgi installed. 

On Ubuntu/Debian systems ``apt-get install libapache2-mod-wsgi``.

Now proceeds installing Apache and required modes:

    # apt-get install apache2 libapache2-mod-wsgi

Enable the mod:

    # a2enmod wsgi

#### Secure Apache Installation

If you want to enable SSL, you need to generate a certificate with OpenSSL or buy one from a certified authority.
You can also use the `make-ssl-cert` utility as following:

    # make-ssl-cert /usr/share/ssl-cert/ssleay.cnf /path/to/apache.pem

Now create a virtual host for the domain you want to host the application on. We'll enable WSGI, SSL and a basic authentication.

A valid template is the following:

    <VirtualHost *:443>
        ServerName yourwebsite.tld

        WSGIDaemonProcess yourapp user=www-data group=www-data processes=1 threads=5
        WSGIScriptAlias / /path/to/app.wsgi

        <Directory /path/to/app.wsgi>
            WSGIProcessGroup yourgroup
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>

        <Location />
            AuthType Basic
            AuthName "Authentication Required"
            AuthUserFile "/path/to/users"
            Require valid-user
        </Location>

        SSLEngine on
        SSLCertificateFile /path/to/apache.pem

        ErrorLog /path/to/error.log
        LogLevel warn
        CustomLog /path/to/access.log combined
        ServerSignature Off
    </VirtualHost>

Now add your user:

    # htpasswd -c /path/to/users username

You should be ready to go. Make sure to reload Apache afterwards:

    # service apache2 reload

#### Unauthenticated Apache 2.4.x Installation

    <VirtualHost *:80>
        ServerName localhost
    
        WSGIDaemonProcess localhost user=www-data group=www-data processes=1 threads=5
        WSGIScriptAlias / /opt/vxcage/app.wsgi
    
        <Directory /opt/vxcage>
            WSGIProcessGroup localhost
            WSGIApplicationGroup %{GLOBAL}
            <Files app.wsgi>
                Require all granted
            </Files>
        </Directory>
    
    
        ErrorLog /opt/vxcage/error.log
        LogLevel debug
        CustomLog /opt/vxcage/access.log combined
        ServerSignature Off
    </VirtualHost>


You should be ready to go. Make sure to reload Apache afterwards:

    # service apache2 reload


Test Installation (Pure Python)
------------

For testing purposes, you can also run it with the Bottle.py server just doing:

    $ python api.py

Usage
-----

You can interact with your repository with the provided REST API.

Submit a sample:

    $ curl -F file=@sample.exe -F tags="tag1 tag2" http://yourdomain.tld/malware/add

Retrieve a sample:

    $ curl http://yourdomain.tld/malware/get/<sha256> > sample.exe

Find a sample by MD5:

    $ curl -F md5=<md5> http://yourdomain.tld/malware/find

Find a sample by SHA-256:

    $ curl -F sha256=<sha256> http://yourdomain.tld/malware/find

Find a sample by Ssdeep (can also search for a substring of the ssdeep hash):

    $ curl -F ssdeep=<pattern> http://yourdomain.tld/malware/find

Find a sample by import hash (md5):

     $ curl -F imphash=<imphash> http://yourdomain.tld/malware/find

Find a sample by Tag:

    $ curl -F tag=<tag> http://yourdomain.tld/malware/find

List existing tags:

    $ curl http://yourdomain.tld/tags/list

Retrieve total (estimated) number of samples:

    $ curl http://yourdomain/malware/total


In case you added a basic authentication, you will need to add `--basic -u "user:pass"`. In case you added SSL support with a generated certificate, you will need to add `--insecure` and obviously make the requests to https://yourdomain.tld.


Console
-------

You can also easily interact with your VxCage server using the provided console interface.
In order to run it, you'll need the following dependencies:

* [requests](http://www.python-requests.org) -- `pip install requests`
* [prettytable](http://code.google.com/p/prettytable/) -- `pip install prettytable`
* [progressbar](http://code.google.com/p/python-progressbar/) -- `pip install progressbar`

This is the help message:

    usage: vxcage.py [-h] [-H HOST] [-p PORT] [-s] [-a]

    optional arguments:
      -h, --help            show this help message and exit
      -H HOST, --host HOST  Host of VxCage server
      -p PORT, --port PORT  Port of VxCage server
      -s, --ssl             Enable if the server is running over SSL
      -a, --auth            Enable if the server is prompting an HTTP
                            authentication

As you can see, you can specify the `host`, the `port` and enable SSL and HTTP authentication.
For example, you can launch it simply with:

    $ python vxcage.py --host yourserver.com --port 443 --ssl --auth

You will be prompted with:

      `o   O o   O .oOo  .oOoO' .oOoO .oOo. 
       O   o  OoO  O     O   o  o   O OooO' 
       o  O   o o  o     o   O  O   o O     
       `o'   O   O `OoO' `OoO'o `OoOo `OoO' 
                                    O       
                                 OoO'  by nex

    Username: nex
    Password: 
    vxcage> 

Now you can start typing commands, you can start with:

    vxcage> help
    Available commands:
      help        Show this help
      tags        Retrieve list of tags
      find        Find a file by md5, sha256, ssdeep, tag or date
      get         Retrieve a file by sha256
      add         Upload a file to the server

You can retrieve the list of available tags:

    vxcage> tags
    +------------------------+
    | tag                    |
    +------------------------+
    | banker                 |
    | bot                    |
    | carberp                |
    | citadel                |
    | zeus                   |
    +------------------------+
    Total: 5

You can search for all samples matching a specific tag:

    vxcage> find tag carberp
    +----------------------------------+------------------------------------------------------------------+--------------+---------------------------------------------------+-----------+
    | md5                              | sha256                                                           | file_name    | file_type                                         | file_size |
    +----------------------------------+------------------------------------------------------------------+--------------+---------------------------------------------------+-----------+
    | 719354b4b7b182b30e1de8ce7b417d2f | 689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029 | carberp1.exe | PE32 executable (GUI) Intel 80386, for MS Windows | 132096    |
    | 63d8fd55ebe6e2fa6cc9523df942a9a5 | a6d77a5ba2b5b46a0ad85fe7f7f01063fe7267344c0cecec47985cd1e46fa7a4 | carberp2.exe | PE32 executable (GUI) Intel 80386, for MS Windows | 192512    |
    | ccf43cdc957d09ea2c60c6f57e4600f0 | b998233b85af152596f5087e64c2cadb1466e4f6da62f416ac3126f87c364276 | carberp3.exe | PE32 executable (GUI) Intel 80386, for MS Windows | 186880    |
    +----------------------------------+------------------------------------------------------------------+--------------+---------------------------------------------------+-----------+
    Total: 3

You can view details on a specific sample:

    vxcage> find md5 719354b4b7b182b30e1de8ce7b417d2f
    sha1: 091fcf7378bfc4baec61bc5708e9a64128c5c7e4
    tags: banker,carberp
    file_type: PE32 executable (GUI) Intel 80386, for MS Windows
    file_name: carberp1.exe
    created_at: 2012-12-25 00:37:16
    file_size: 132096
    crc32: 05AF53DC
    ssdeep: 3072:fQAsBL+tnecg1OS+x/+SSQSBX8MxaQhJwox:fQAsBoecg1UM3c
    sha256: 689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029
    sha512: 844e0010e23571e2bc6a44405a012bca4f01955348db26320d6a95e54e6afc85a81bef574ee65de9d67cdf6e2cf80fd4d1b2c559902596943b1e4ebeb5641650
    id: 41
    md5: 719354b4b7b182b30e1de8ce7b417d2f

You can download the sample:

    vxcage> get 689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029 /tmp
    Download: 100% |:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::| Time: 00:00:00 223.63 K/s
    File downloaded at path: /tmp/689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029

Or upload a new one:

    vxcage> add /tmp/malware.exe windows,trojan,something
    File uploaded successfully

Copying
-------

VxCage is licensed under [BSD 2-Clause](http://opensource.org/licenses/bsd-license.php) and is copyrighted to Claudio Guarnieri.


Contacts
--------

Twitter: [@botherder](http://twitter.com/botherder)
