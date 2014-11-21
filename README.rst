====================
python-nessus-client
====================

Python Client for `Nessus 5.0 REST API <http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf>`_.

Nessus is a proprietary comprehensive vulnerability scanner which is developed by Tenable Network Security.
It is free of charge for personal use in a non-enterprise environment.

Documentation
-------------

Documentation is available online at http://python-nessus-client.readthedocs.org and in the ``docs``
directory.

Installation
------------

Install using pip

.. code:: bash

    pip install python-nessus-client

Examples
--------

REST resources are translated to methods.

For example:

+----------------------------------------------+-----------------------------------------------------+
| Resource                                     | Method                                              |
+==============================================+=====================================================+
| ``/users/list``                              | ``object.users.list()``                             |
+----------------------------------------------+-----------------------------------------------------+
| ``/server/securesettings/&proxy%5Fport=8888``| ``object.server.securesettings(proxy_port='8888')`` |
+----------------------------------------------+-----------------------------------------------------+

and so on...

To get users list ``https://nessus.example.com:8834/users/list`` we call ``list()`` method on ``Users`` class

.. code:: python

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
    >>> print nessus.users.list()
    [
      {
        "admin": "TRUE",
        "name": "test",
        "lastlogin": 1416492416
      }
    ]

To get server security settings list ``https://nessus.example.com:8834/server/securesettings/list``
we call ``securesettings()`` method on ``Server`` class

.. code:: python

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
    >>> print nessus.server.securesettings()
    {
      "proxysettings": {
        "proxy_password": null,
        "proxy_port": "8080",
        "custom_host": null,
        "proxy_username": null,
        "user_agent": null,
        "proxy": "10.0.0.1"
      }
    }

To set server security settings ``https://nessus.example.com:8834/server/securesettings``
we use the same ``securesettings()`` method on ``Server`` class but we pass
as a argument settings to set up.

.. code:: python

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
    >>> nessus.server.securesettings(proxy_port='8081')
    >>> print nessus.server.securesettings()
    {
      "proxysettings": {
        "proxy_password": null,
        "proxy_port": "8081",
        "custom_host": null,
        "proxy_username": null,
        "user_agent": null,
        "proxy": "10.0.0.1"
      }
    }

More examples can be found in the following subsections and in class documentation.

Authenticating a user
^^^^^^^^^^^^^^^^^^^^^

Login to Nessus server

.. code:: python

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')

Response is Python structure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We can acts like we work with dict.

Get configuration value

.. code:: python

    >>> print nessus.server.securesettings()['proxysettings']['proxy_port']
    8080

Get name from second item in report list get list of hosts contained in a specified report

.. code:: python

    >>> second_host = nessus.report.list()[1]['name']
    >>> print nessus.report.hosts(second_host)
    {
      "scanprogresscurrent": "0",
      "scanprogresstotal": "100",
      (...)
    }

Make output more readable
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: python

    # before
    >>> print nessus.server.securesettings()
    {u'proxysettings': {u'proxy_password': None, u'proxy_port': u'8080', (...)
    # after
    >>> import json
    >>> data = nessus.server.securesettings()
    >>> json.dumps(data, indent=2)
    {
      "proxysettings": {
        "proxy_password": null,
        "proxy_port": "8080",
        "custom_host": null,
        "proxy_username": null,
        "user_agent": null,
        "proxy": "10.0.0.1"
      }
    }

Check if report has audit trail

.. code:: python

    >>> nessus.report.has_audit_trail(name)
    True
    >>> if nessus.report.has_audit_trail(name):
    >>>    print 'Report {} has audit trail'.format(name)
    Report 95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309 has audit trail

Create new scan

.. code:: python

    # make list with hosts
    >>> target = ['localhost', 'example.com']
    >>> nessus.scan.new(target, 'test', '-37')
