VxCage
======

VxCage is a WSGI Python application for managing a malware samples repository with a REST API interface.

Installation
------------

In order to install VxCage you need to have Python (2.7), pip, and git installed. 

Following are the required libraries:

If you want to enable the fuzzy hash, you need to install.

* [ssdeep](http://ssdeep.sourceforge.net/) and the Python bindings, [pydeep](https://github.com/kbandla/pydeep).

On Ubuntu/Debian systems ``sudo apt-get install ssdeep libfuzzy-dev``

### Database - PostgreSQL

This fork of VxCage *requires* PostgreSQL in order to take advantage of native json data types.

To install PostgreSQL requirements:

On Ubuntu/Debian systems ``apt-get install postgresql postgresql-contrib postgresql-server-dev-all libpq-dev``.

You also need to configure the connection string for your database in `etc/api.conf`. For example:

PostgreSQL:

    postgresql://user:pass@host/database

Refer to [SQLAlchemy](http://docs.sqlalchemy.org/en/latest/core/engines.html)'s documentation for additional connection string details.


Python Dependencies
------------
 
If they are installed, you can install the required Python packages via pip.
 
 * ``pip install -r requirements.txt``
 
Development dependencies
---------
 
You can install the required Python packages via pip.
 
 * ``pip install -r dev-requirements.txt``

### Apache Installation

If you plan to run VxCage with Apache, you'll need to have mod_wsgi installed. 

On Ubuntu/Debian systems ``apt-get install libapache2-mod-wsgi``.

Now proceeds installing Apache and required modes:

    # apt-get install apache2 libapache2-mod-wsgi

Enable the mod:

    # a2enmod wsgi

#### Secure Apache Configuration

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

#### Unauthenticated Apache 2.4.x Configuration

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

Standalone webserver (Pure Python)
------------

For testing purposes, you can also run it with the Bottle.py server just doing:

    $ invoke webserver

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

You can also easily interact with your VxCage server using the provided console interface from either a remote or localmachine.

You will need python 2.7, and pip installed.

In order to run it, you'll need the following dependencies:

* ``pip install -r client-requirements.pip``

The client can be found on the server in ``bin\vxcage.py`` 

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
      tags         Retrieve list of tags
      find         Query a file by md5, sha256, ssdeep, imphash, tag or date
      get          Retrieve a file by sha256
      add          Upload a file to the server
      total        Total number of samples
      version      Version of remote vxcage server
      
      help         Show this help
      exit | quit  Exit cli application

You can interrogate the server:

    vxcage> version
    +---------+------------------------------------+
    | Key     | Value                              |
    +---------+------------------------------------+
    | source  | https://github.com/shadowbq/vxcage |
    | version | 1.3.0                              |
    +---------+------------------------------------+


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

    vxcage> find sha256 b4c5ecdb80ac097eaed5299c8f66cd56ebfe502e33aecf7ecfb6c34efc9f42ac
    peid: None
    sha1: 20ccd7830548e8ad90216f1473ce4d7f3748b1a8
    virustotal: -/- matches
    tags: upxed
    file_type: None
    imphash: None
    created_at: 2014-08-02 04:59:19.937406
    file_size: 166912
    pdfid: {u'pdfid': -1}
    file_name: puttytel.exe
    crc32: 51799BDB
    ssdeep: 3072:lWVW9uWonxEXJXcUuu45mrCDc+hzWXyi:4I9snxE5XUTs+hzW
    sha256: b4c5ecdb80ac097eaed5299c8f66cd56ebfe502e33aecf7ecfb6c34efc9f42ac
    sha512: be6286f1d79b4aca1a1e504fcc270820803af3c64cf9a570a3a22588734c4cb7a3cef460cccbbd984fcfb6b91fb32108819952859c5baf73fe588fe8372abae5
    id: 7
    md5: a8b41b32131ca34387d2929c19eaa7d4

You can download the sample:

    vxcage> get 689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029 /tmp
    Download: 100% |:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::| Time: 00:00:00 223.63 K/s
    File downloaded at path: /tmp/689a35928f71848fab346b50811c6c0aab95da01b9293c60d74c7be1357dc029

Or upload a new one:

    vxcage> add /tmp/malware.exe windows,trojan,something
    File uploaded successfully

Copying
-------

See LICENSE file

VxCage is licensed originally under [BSD 2-Clause](http://opensource.org/licenses/bsd-license.php) and is copyrighted to Claudio Guarnieri.


Contacts
--------

Twitter: [@botherder](http://twitter.com/botherder)
