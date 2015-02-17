from requests import Request, Session, codes
import os

VERSION = (0, 1, 1)
__version__ = '.'.join(map(str, VERSION))
__author__ = 'Lukasz Banasiak'
__all__ = ['API', ]


class Resource(object):
    def __init__(self, uri, api):
        self.uri = uri
        self.api = api

    @staticmethod
    def _nessus_dict2dict(self, data, key=0):
        """ Convert from {key: key, value: value} to {key: value} dict

        :param data: nessus dict response
        :param key: which value should be key, first or second
        """
        new = {}
        k, v = 0, 1
        if key == 1:
            v, k = 0, 1
        for r in data:
            new[r.values()[k]] = r.values()[v]
        return new


class Server(Resource):

    def securesettings(self, **kwargs):
        """Requests or update the Nessus server settings

        Proxy information, User-Agent, and custom update host.

        :param kwargs: settings name and value to change (e.g. ``proxy='example.com'``)

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.server.securesettings()
            {u'proxysettings': {u'proxy_password': None, u'proxy_port': u'8080', (...)
            >>> nessus.server.securesettings(proxy_port='8081')
            >>> print nessus.server.securesettings()
            {u'proxysettings': {u'proxy_password': None, u'proxy_port': u'8081', (...)
            >>> print nessus.server.securesettings()['proxysettings']['proxy_port']
            8081
        """
        if kwargs:
            return self.api.post(self.uri+'/securesettings', data=kwargs)
        else:
            return self.api.get(self.uri+'/securesettings/list')['securesettings']

    def preferences(self, **kwargs):
        """Requests or update the Nessus server advanced settings.

        :param kwargs: settings name and value to change (e.g. ``checks_read_timeout=5``)

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.server.preferences()
            {
              "xmlrpc_listen_port": "8834",
              "auto_update_delay": "24",
              "nasl_log_type": "none",
              "log_whole_attack": "no",
              "optimize_test": "yes",
              (...)
            }
            >>> nessus.server.preferences(xmlrpc_listen_port=8845)
            >>> print nessus.server.preferences()
            {
              "xmlrpc_listen_port": "8845",
              "auto_update_delay": "24",
              "nasl_log_type": "none",
              "log_whole_attack": "no",
              "optimize_test": "yes",
              (...)
            }
            >>> print nessus.server.preferences()['xmlrpc_listen_port']
            8845
        """
        if kwargs:
            # get all current settings
            payload = self.preferences()
            # update with new settings
            payload.update(kwargs)
            return self.api.post(self.uri+'/preferences', data=payload)
        else:
            response = self.api.get(self.uri+'/preferences/list')['serverpreferences']['preference']
            data = self._nessus_dict2dict(self, response)
            return data

    def update(self):
        """Directs the Nessus server to force a plugin update.

        Note that if the server is not yet registered, then authentication is not required.
        Once the server is registered with a Nessus Feed ID,
        then the request must be made as an authenticated administrator.

        Permissions:

        * authenticated: Yes
        * administrator: Yes
        """
        return self.api.post(self.uri+'/update')

    def register(self, code):
        """Registers the Nessus server with Tenable Network Security using the plugin feed registration code.

        :param code: a Nessus plugin feed registration code

        Permissions:

        * authenticated: No
        * administrator: No
        """
        params = {'code': code}
        return self.api.post(self.uri+'/register', **params)

    def restart(self):
        """Directs the Nessus server to restart.

        This function is only valid during the initial installation and registration process.

        Permissions:

        * authenticated: No
        * administrator: No
        """
        return self.api.get(self.uri+'/restart')

    def load(self):
        """Requests the current Nessus server load and platform type.

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        return self.api.get(self.uri+'/load')


class Users(Resource):

    def add(self, login, password, admin=False):
        """Creates a new user in the Nessus user's database.

        This effectively creates the user and its home directory on disk.
        The login must match the regex ``^[a-zA-Z0-9.@-]+$``.
        Only an administrator can create another user.

        :param login: name of the user to create
        :param password: password for this user
        :param admin: set to 1 if the new user will be declared as an administrator

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        Example::

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
            >>> nessus.users.add('test2', 'pass2')
            >>> print nessus.users.list()
            [
              {
                "admin": "TRUE",
                "name": "test",
                "lastlogin": 1416492416
              },
              {
                "admin": "FALSE",
                "name": "test2"
              }
            ]

        .. todo:: add login regexp verification ``^[a-zA-Z0-9.@-]+$``
        """
        # TODO: add login regexp verification ^[a-zA-Z0-9.@-]+$
        payload = {
            'login': login,
            'password': password,
            'admin': 0
        }
        if admin:
            payload.update(admin=1)
        return self.api.post(self.uri+'/add', data=payload)

    def delete(self, login):
        """Deletes an existing user.

        Under the hood, this will delete the user home directory (i.e., ``/opt/nessus/var/nessus/users/<userName>/``),
        including this user's policies and reports.

        :param login: name of the user to delete

        Permissions:

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> nessus.users.delete('test2')

        * authenticated: Yes
        * administrator: Yes
        """
        payload = {'login': login}
        return self.api.post(self.uri+'/delete', data=payload)

    def edit(self, login, password=None, admin=None):
        """Edits the details of an existing user.

        The user's password and admin status can be modified, however the username cannot be.

        :param login: name of the user to edit
        :param password: password of the user
        :param admin: True for yes, False for no

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        Example:

        Set new password for user test2::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> nessus.users.edit('test2', password='newpass')

        Make user test2 admin::

            >>> nessus.users.edit('test2', admin=True)
            >>> print nessus.users.list()
            [
              (...),
              {
                "admin": "TRUE",
                "name": "test2"
              }
            ]
        """
        payload = {'login': login}
        if password:
            payload.update(password=password)
        if admin is not None:
            payload.update(admin=int(admin))
        return self.api.post(self.uri+'/edit', data=payload)

    def chpasswd(self, password):
        """Lets a user or administrators change their password.

        :param password: the user's password to be changed

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> nessus.users.chpasswd('turbotajnehaslo')
        """
        payload = {
            'login': self.api.username,
            'password': password,
        }
        return self.api.post(self.uri+'/chpasswd', data=payload)

    def list(self):
        """Lists the users on the Nessus scanner.

        The result contains their administrator status and the time they last logged in.

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        Example::

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
        """
        return self.api.get(self.uri+'/list')['users']['user']


class Plugins(Resource):

    def list(self, family=None):
        """List of plugin families loaded by the remote server.

        List as well as the number of plugins of each family and list of plugins contained in the family.

        :param family: the plugin family to list

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.plugins.list()
            {
              "Mandriva Local Security Checks": "2871",
              "Windows : Microsoft Bulletins": "948",
              "Netware": "14",
              "Misc.": "911",
              "CGI abuses": "3127",
              "Policy Compliance": "37",
              (...)
            }
            >>> print nessus.plugins.list(family='AIX Local Security Checks')
            [
              {
                "pluginid": "55364",
                "pluginfilename": "aix_U840865.nasl",
                "pluginname": "AIX 530011 : U840865",
                "pluginfamily": "AIX Local Security Checks"
              },
              {
                "pluginid": "54191",
                "pluginfilename": "aix_U837183.nasl",
                "pluginname": "AIX 710000 : U837183",
                "pluginfamily": "AIX Local Security Checks"
              },
              (...)
            ]
        """
        if family:
            payload = {'family': family}
            return self.api.post(self.uri+'/list/family', data=payload)['pluginlist']['plugin']
        else:
            response = self.api.post(self.uri+'/list')['pluginfamilylist']['family']
            data = self._nessus_dict2dict(self, response, key=1)
            return data

    def attributes(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/plugins/attributes/list``
        """
        # TODO: /plugins/attributes/list
        raise NotImplementedError

    def attributes_list_family_search(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/plugins/attributes/familySearch``
        """
        # TODO: /plugins/attributes/familySearch
        raise NotImplementedError

    def attributes_list_plugin_search(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/plugins/attributes/pluginSearch``
        """
        # TODO: /plugins/attributes/pluginSearch
        raise NotImplementedError

    def description(self, fname):
        """Description of a given plugin including its cross references and more.

        The file name of the plugin (e.g., ping_host.nasl) must be passed as an argument.

        :param fname: the name of the plugin to describe (filename)

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.plugins.description('aix_U811383.nasl')
            {
              "pluginattributes": {
                "description": "The remote host is missing AIX PTF U811383 which is related to the security of the package rsct.basic.hacmp.2.3.11.0 You should install this PTF for your system to be up-to-date.",
                "plugin_version": "$Revision: 1.4 $",
                "plugin_modification_date": "2011/03/14",
                "solution": "Run ' suma -x -a RqType=Security ' on the remote system",
                "risk_factor": "High",
                "synopsis": "The remote host is missing a vendor supplied security patch",
                "plugin_publication_date": "2008/02/12",
                "plugin_type": "local"
              },
              "pluginid": "30766",
              "pluginname": "AIX 520009 : U811383",
              "pluginfamily": "AIX Local Security Checks"
            }
        """
        payload = {'fname': fname}
        return self.api.post(self.uri+'/description', data=payload)['plugindescription']

    def preferences(self):
        """List of plugin-defined preferences.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.plugins.preferences()
            [
              {
                "preferencetype": "entry",
                "fullname": "ADSI Settings[entry]:Domain Controller :",
                "preferencename": "Domain Controller :",
                "pluginname": "ADSI Settings",
                "preferencevalues": null
              },
              (...)
            ]
        """
        return self.api.get(self.uri+'/preferences')['pluginspreferences']['item']

    def md5(self):
        """List of plugin file names and corresponding MD5 hashes.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.plugins.md5()
            [
              "aix_U807831.nasl": "cfb861054ad33224cb9f76cd465cea04",
              "aix_U829081.nasl": "79159fa868a6bf266a004a2abcda08e5",
              "fedora_2004-313.nasl": "cc8281f624420f0d03a530cb015eab89",
              (...)
            ]
        """
        response = self.api.post(self.uri+'/md5')['entries']['entry']
        data = self._nessus_dict2dict(self, response, key=1)
        return data

    def descriptions(self):
        """List of all plugin descriptions from the Nessus server.

        Permissions:

        * authenticated: Yes
        * administrator: Yes

        .. warning:: This request returns a very large response (e.g., over 10 MB).
        """
        return self.api.post(self.uri+'/descriptions')


class Preferences(Resource):

    def list(self):
        """List of settings from the ``nessusd.conf`` file.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.preferences.list()
            {
              "listen_port": "1241",
              "max_hosts": "80",
              "auto_update": "yes",
              "throttle_scan": "yes",
              (...)
            }
        """
        response = self.api.get(self.uri+'/list')['serverpreferences']['preference']
        data = self._nessus_dict2dict(self, response)
        return data


class Policy(Resource):

    def list(self):
        """List of available policies, policy settings and the default values that would be used when creating a new Nessus scan.

        The list of default values are the values that will be used during a scan
        if they are not supplied by the user in the policy (taken from nessusd.rules).

        For example, you could save a policy with only one item in it (e.g., ``max_checks = 42``)
        and the rest of the settings used for the scan would be what is returned in :class:`~nessus.Policy.list()`.
        Custom policies that are returned only include enabled plugins (i.e., disabled plugins will not be returned).

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.policy.list()
            [
              {
                "policyname": "Internal Network Scan",
                "policycontents": {
                  "individualpluginselection": {
                    "pluginitem": [
                      {
                        "status": "enabled",
                        "pluginid": "34220",
                        "pluginname": "Netstat Portscanner (WMI)",
                        "family": "Port scanners"
                      },
                      (...)
        """
        return self.api.get(self.uri+'/list')['policies']['policy']

    def delete(self, policy_id):
        """Delete an existing policy.

        :param policy_id: numeric ID of the policy

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'policy_id': policy_id}
        return self.api.post(self.uri+'/delete', data=payload)

    def copy(self, policy_id):
        """Copy an existing policy to a new policy.

        :param policy_id: numeric ID of the policy

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'policy_id': policy_id}
        return self.api.post(self.uri+'/copy', data=payload)

    def add(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/policy/add``
        """
        raise NotImplementedError

    def edit(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/policy/edit``
        """
        # TODO: /policy/edit
        raise NotImplementedError

    def download(self, policy_id):
        """Download the policy from the Nessus scanner to your local system.

        :param policy_id: numeric ID of the policy

        Permissions:

        * authenticated: Yes
        * administrator: Yes
        """
        payload = {'policy_id': policy_id}
        return self.api.get(self.uri+'/download', params=payload)

    def upload(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/file/upload``, ``/file/policy/import``
        """
        # TODO: /file/upload then /file/policy/import
        raise NotImplementedError


class Scan(Resource):

    def new(self, target, scan_name, policy_id):
        """Create a new scan job.

        The target parameter is a list, tuple or comma separated string,
        under any form of target specification (e.g., hostname, IP, range, etc.).

        :param target: list, tuple or comma separated string
        :param scan_name: a name for the scan job
        :param policy_id: numeric ID of the policy to use for the scan

        Permissions:

        * authenticated: Yes
        * administrator: No

        .. note:: Once a scan is created, it is assigned a Universally Unique ID (UUID) that will be used on all
            further requests related to that scan.

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> target = ['localhost', 'example.com']
            >>> nessus.scan.new(target, 'test', '-37')
        """
        payload = {
            'target': target,
            'scan_name': scan_name,
            'policy_id': policy_id,
        }
        if isinstance(target, (list, tuple)):
            payload['target'] = ','.join(target)
        return self.api.post(self.uri+'/new', data=payload)

    def stop(self, scan_uuid):
        """Stop an existing scan job.

        :param scan_uuid: UUID of scan job to stop

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'scan_uuid': scan_uuid}
        return self.api.post(self.uri+'/stop', data=payload)

    def pause(self, scan_uuid):
        """Pause an existing scan job, allowing it to be resumed at a later time.

        :param scan_uuid: UUID of scan job to pause

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'scan_uuid': scan_uuid}
        return self.api.post(self.uri+'/pause', data=payload)

    def resume(self, scan_uuid):
        """Resume a previously paused scan job.

        :param scan_uuid: UUID of scan job to resume

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'scan_uuid': scan_uuid}
        return self.api.post(self.uri+'/resume', data=payload)

    def list(self):
        """List all current scan jobs.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.scan.list()
            {
              "templates": {},
              "policies": {
                "policies": {
                  "policy": [
                    {
                      "user_permissions": 128,
                      "policyName": "Internal Network Scan",
                      "policyOwner": "test",
                      "policyID": -1,
                      "visibility": "shared"
                    },
                    (...)
                  ]
                }
              },
              "scans": {
                "scanList": {
                  "scan": []
                }
              }
            }
        """
        return self.api.post(self.uri+'/list')

    def template_new(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/scan/template/new``
        """
        # TODO: /scan/template/new
        raise NotImplementedError

    def template_edit(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/scan/template/edit``
        """
        # TODO: /scan/template/edit
        raise NotImplementedError

    def template_delete(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/scan/template/delete``
        """
        # TODO: /scan/template/delete
        raise NotImplementedError

    def template_launch(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/scan/template/launch``
        """
        # TODO: /scan/template/launch
        raise NotImplementedError


class Report(Resource):

    def list(self):
        """List of available scan reports.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.report.list()
            [
              {
                "status": "imported",
                "timestamp": 1416478505,
                "name": "95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309",
                "readableName": "Test Scan"
              },
              (...)
            ]
        """
        return self.api.get(self.uri+'/list')['reports']['report']

    def delete(self, report):
        """Delete a specified report.

        :param report: UUID of the report to be deleted

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'report': report}
        return self.api.post(self.uri+'/delete', data=payload)

    def hosts(self, report):
        """List of hosts contained in a specified report.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()
            [
              {
                "status": "imported",
                "timestamp": 1416478505,
                "name": "95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309",
                "readableName": "Test Scan"
              },
              (...)
            ]
            >>> print nessus.report.hosts('95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309')
            {
              "scanprogresscurrent": "0",
              "scanprogresstotal": "100",
              "totalchecksconsidered": "100",
              "hostname": "127.0.0.1",
              "numchecksconsidered": "100",
              "severitycount": {
                "item": [
                  {
                    "severitylevel": "0",
                    "count": "0"
                  },
                  {
                    "severitylevel": "1",
                    "count": "10"
                  },
                  {
                    "severitylevel": "2",
                    "count": "0"
                  },
                  {
                    "severitylevel": "3",
                    "count": "1"
                  }
                ]
              },
              "severity": "11"
            }

        Get second host name from list and pass as arg to :class:`~nessus.Report.hosts()`::

            >>> second_host = nessus.report.list()[1]['name']
            >>> print nessus.report.hosts(second_host)
            {
              "scanprogresscurrent": "0",
              "scanprogresstotal": "100",
              (...)
            }
        """
        payload = {'report': report}
        return self.api.post(self.uri+'/hosts', data=payload)['hostlist']['host']

    def ports(self, report, hostname):
        """List of ports, and the number of findings on each port for each severity.

        Severities: Info, Low, Medium, High, Critical

        :param report: UUID of the report
        :param hostname: name of host to display open ports for

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()[0]['name']
            >>> print nessus.report.ports(name, '127.0.0.1')
            [
              {
                "svcname": "general",
                "portnum": "0",
                "protocol": "tcp",
                "severity": "3",
                "severitycount": {
                  "item": [
                    {
                      "severitylevel": "0",
                      "count": "0"
                    },
                    {
                      "severitylevel": "1",
                      "count": "2"
                    },
                    {
                      "severitylevel": "2",
                      "count": "0"
                    },
                    {
                      "severitylevel": "3",
                      "count": "1"
                    }
                  ]
                }
              }, (...)
        """
        payload = {
            'report': report,
            'hostname': hostname,
        }
        return self.api.post(self.uri+'/ports', data=payload)['portlist']['port']

    def details(self, report, hostname, port, protocol):
        """Details of a scan for a given host.

        :param report: UUID of the report
        :param hostname: name of host to display scan details for
        :param port: port to display scan results for
        :param protocol: protocol of open port on host to display scan details for

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()[0]['name']
            >>> print nessus.report.details(name, '127.0.0.1', '0', 'tcp')
            [
              {
                "severity": "1",
                "pluginid": "19506",
                "pluginname": "Nessus Scan Information",
                "item_id": "117",
                "data": {
                  "description": "This script displays, for each tested host, information about the scan itself :(...)",
                  "plugin_modification_date": "2014/06/20",
                  "plugin_name": "Nessus Scan Information",
                  "plugin_publication_date": "2005/08/26",
                  "script_version": "$Revision: 1.69 $",
                  "solution": "n/a",
                  "risk_factor": "None",
                  "synopsis": "Information about the Nessus scan.",
                  "fname": "scan_info.nasl",
                  "plugin_type": "summary",
                  "@xmlns:cm": "http://www.nessus.org/cm"
                },
                "port": "general/tcp"
              },(...)

        .. todo:: check if all args are required
        """
        # TODO: check if all args are required
        payload = {
            'report': report,
            'hostname': hostname,
            'port': port,
            'protocol': protocol
        }
        return self.api.post(self.uri+'/details', data=payload)['portdetails']['reportitem']

    def tags(self, report, hostname):
        """Tags of a scan for a given host.

        Some plugins can create "tags" for a remote host that can be extracted later.
        For example, the OS fingerreturn plugin creates the tag "operating-system" with the actual OS as a value.
        This makes it easier to extract data automatically.

        :param report: UUID of the report
        :param hostname: name of host to display scan details for

        Permissions:

        * authenticated: Yes
        * administrator: No

        .. note:: "Tags" cover plugin-supplied information, such as the OS name, type of credentials used, etc.
        """
        payload = {
            'report': report,
            'hostname': hostname
        }
        return self.api.post(self.uri+'/tags', data=payload)

    def has_audit_trail(self, report):
        """Determine if a specified report has an Audit Trail associated with it.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()[0]['name']
            >>> nessus.report.has_audit_trail(name)
            True
            >>> if nessus.report.has_audit_trail(name):
            >>>    print 'Report {} has audit trail'.format(name)
            Report 95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309 has audit trail
        """
        payload = {'report': report}
        response = self.api.post(self.uri+'/hasAuditTrail', data=payload)['hasAuditTrail']
        if response == 'TRUE':
            return True
        elif response == 'FALSE':
            return False
        else:
            return None

    def attributes(self, report):
        """List of filter attributes associated with a given report.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'report': report}
        return self.api.post(self.uri+'/attributes/list', data=payload)['reportattributes']['attribute']

    def errors(self, report):
        """List of any errors associated with a given report.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No
        """
        payload = {'report': report}
        return self.api.post(self.uri+'/errors', data=payload)

    def has_kb(self, report):
        """Determine if a specified report has a KB associated with it.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()[0]['name']
            >>> nessus.report.has_kb(name)
            True
            >>> if nessus.report.kb(name):
            >>>    print 'Report {} has a KB associated with it'.format(name)
            Report 95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309 has a KB associated with it
        """
        payload = {'report': report}
        response = self.api.post(self.uri+'/hasKB', data=payload)['hasKB']
        if response == 'TRUE':
            return True
        elif response == 'FALSE':
            return False
        else:
            return None

    def can_delete_item(self, report):
        """Determine if a specified report allows items to be deleted.

        :param report: UUID of the report

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> name = nessus.report.list()[0]['name']
            >>> nessus.report.can_delete_item(name)
            True
            >>> if nessus.report.can_delete_item(name):
            >>>    print 'Report {} allows items to be deleted'.format(name)
            Report 95c309f8-2578-fd3e-9e4d-a8aa6d6511e8b617b5a088c93309 allows items to be deleted
        """
        payload = {'report': report}
        response = self.api.post(self.uri+'/canDeleteItems', data=payload)['canDelete']
        if response == 'TRUE':
            return True
        elif response == 'FALSE':
            return False
        else:
            return None

    def trail_details(self, report, hostname, plugin_id):
        """Audit trail details for a specified report.

        :param report: UUID of the report
        :param hostname: host name or IP (optional)
        :param plugin_id: numeric ID of a Nessus plugin

        Permissions:

        * authenticated: Yes
        * administrator: No

        .. todo:: check if all args are required
        """
        # TODO: check if all args are required
        payload = {
            'report': report,
            'hostname': hostname,
            'plugin_id': plugin_id
        }
        return self.api.post(self.uri+'/trail-details', data=payload)['audit_trail']['trail']

    def download(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/file/report/download``, ``/chapter``, ``/chapter/list``, ``/file/xslt``, ``/file/xslt/list``
        """
        # TODO: /file/report/download, /chapter, /chapter/list, /file/xslt, /file/xslt/list
        raise NotImplementedError

    def upload(self, path):
        """
        :raise NotImplementedError:

        .. todo:: ``/file/report/import``
        """
        # TODO: /file/report/import
        raise NotImplementedError

    # TODO: /report2/*


class File(Resource):

    def upload(self, path, filedata=None):
        """This function uploads a file to the Nessus server.

        The uploaded file is saved with the name given by the Filedata argument.
        This function is used when a ``.nessus`` or ``.audit`` file is needed for another function.

        Functions requiring file upload:

        * :class:`~nessus.Report.upload()`
        * :class:`~nessus.Policy.upload()`

        Functions that may use uploaded files:

        * :class:`~nessus.Policy.add()`
        * :class:`~nessus.Report.edit()`

        :param path: path to the file to be uploaded
        :param filedata: name to use when saving the uploaded file to the Nessus server
        """
        filename = os.path.split(path)[-1]  # get filename.ext
        if not filedata:
            filedata = filename.split('.')[0]  # get filename
        files = {filedata: (filename, open(path, 'r'), 'application/octet-stream')}
        return self.api.post(self.uri+'/upload', files=files)

    def xslt(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/file/xslt``, ``/file/xslt/list``
        """
        # TODO: /file/xslt
        # TODO: /file/xslt/list
        raise NotImplementedError

    def chapter(self):
        """
        :raise NotImplementedError:

        .. todo:: ``/chapter``, ``/chapter/list``
        """
        # TODO: /chapter
        # TODO: /chapter/list
        raise NotImplementedError


class API(object):
    """Main API class

    :param base_url: IP:PORT or FQDN:PORT of Nessus Server
    :param username: user login
    :param password: user password
    :param bool login: disable autologin to Nessus Server
    :param bool debug: enable DEBUG mode

    Example::

        >>> from nessus import API
        >>> nessus = API('https://127.0.0.1:8834', login=False)
        >>> nessus.login('user', 'pass')

    Is equivalent of::

        >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
    """
    def __init__(self, base_url, username='', password='', login=True, debug=False):
        if debug:
            import logging
            try:
                import http.client as http_client
            except ImportError:
                # Python 2
                import httplib as http_client
            http_client.HTTPConnection.debuglevel = 1
            logging.basicConfig(level=0)
        super(API, self).__init__()
        self.base_url = base_url + '/' if not base_url.endswith('/') else base_url
        self.username = username
        self.payload = {'json': 1}  # set return type to JSON
        self.session = Session()

        if login:
            self.login(self.username, password)

        self.server = Server('server', api=self)
        self.users = Users('users', api=self)
        self.plugins = Plugins('plugins', api=self)
        self.preferences = Preferences('preferences', api=self)
        self.policy = Policy('policy', api=self)
        self.scan = Scan('scan', api=self)
        self.report = Report('report', api=self)
        self.file = File('file', api=self)

    def get(self, name, **payload):
        try:
            payload['params'].update(self.payload)
        except KeyError:
            payload['params'] = self.payload
        return self.__request('GET', name, **payload)

    def post(self, name, **payload):
        try:
            payload['data'].update(self.payload)
        except KeyError:
            payload['data'] = self.payload
        return self.__request('POST', name, **payload)

    def __request(self, method, name, **payload):
        request = Request(method, self.base_url + name, **payload)
        prepped = self.session.prepare_request(request)
        respond = self.session.send(prepped, verify=False)
        if respond.status_code == codes.ok:
            try:
                return respond.json()['reply']['contents']
            except KeyError:
                raise Exception('Response malformed.')

    def login(self, login, password):
        """Authenticates a user.

        Permissions:

        * authenticated: No
        * administrator: No

        :param login: user login
        :param password: user password

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', login=False)
            >>> nessus.login('user', 'pass')
        """
        payload = {'login': login, 'password': password}
        self.post('login', data=payload)

    def logout(self):
        """Log out a user.

        It invalidates the token and performs some "house-cleaning" tasks
        such as deleting the temporary files created for that user.

        Permissions:

        * authenticated: Yes
        * administrator: No

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> nessus.logout()
        """
        self.post('logout')

    def feed(self):
        """Current plugin feed information from the server.

        This will return the feed type (HomeFeed vs. ProfessionalFeed), Nessus version and integrated web server version.

        Permissions:

        * authenticated: Yes
        * administrator: No

        :return: Feed information.

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.feed()
        """
        return self.post('/feed')

    def uuid(self):
        """Nessus server UUID.

        Permissions:

        * authenticated: Yes
        * administrator: No

        :return: Server information

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.uuid()
        """
        return self.get('/uuid')

    def get_cert(self):
        """Nessus server certificate.

        Permissions:

        * authenticated: Yes
        * administrator: No

        :return: Server certificate

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.get_cert()
        """
        return self.post('/getcert')

    def timezones(self):
        """Lists time zones that can be specified in a scheduled scan policy.

        Permissions:

        * authenticated: Yes
        * administrator: No

        :return: List of time zones

        Example::

            >>> from nessus import API
            >>> nessus = API('https://127.0.0.1:8834', username='user', password='pass')
            >>> print nessus.timezones()
        """
        return self.post('/timezones')