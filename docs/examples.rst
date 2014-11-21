Examples
========

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

To get users list ``https://nessus.example.com:8834/users/list`` we call :class:`~nessus.Users.list()` method
on :class:`~nessus.Users` class

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
we call :class:`~nessus.Server.securesettings()` method on :class:`~nessus.Server` class

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

To set server security settings ``https://nessus.example.com:8834/server/securesettings/&proxy%5Fport=8888``
we use the same :class:`~nessus.Server.securesettings()` method on :class:`~nessus.Server` class but we pass
as a argument settings to set up.

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
    >>> nessus.server.securesettings(proxy_port='8888')
    >>> print nessus.server.securesettings()
    {
      "proxysettings": {
        "proxy_password": null,
        "proxy_port": "8888",
        "custom_host": null,
        "proxy_username": null,
        "user_agent": null,
        "proxy": "10.0.0.1"
      }
    }

More examples can be found in the following subsections and in class documentation:

* :class:`~nessus.API`
* :class:`~nessus.Server`
* :class:`~nessus.Users`
* :class:`~nessus.Plugins`
* :class:`~nessus.Policy`
* :class:`~nessus.Scan`
* :class:`~nessus.Report`

Authenticating a user
---------------------

Login to Nessus server

    >>> from nessus import API
    >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')

Response is Python structure
----------------------------

We can acts like we work with dict.

Get configuration value

    >>> print nessus.server.securesettings()['proxysettings']['proxy_port']
    8080

Get name from second item in report list get list of hosts contained in a specified report

    >>> second_host = nessus.report.list()[1]['name']
    >>> print nessus.report.hosts(second_host)
    {
      "scanprogresscurrent": "0",
      "scanprogresstotal": "100",
      (...)
    }

Make output more readable
-------------------------

Before

    >>> print nessus.server.securesettings()
    {u'proxysettings': {u'proxy_password': None, u'proxy_port': u'8080', (...)

After

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
