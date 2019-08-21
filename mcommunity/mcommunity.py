import requests
import json
import logging
import re
import time

from urllib.parse import quote
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


class Client:

    def __init__(self, config):
        """Initialize a new Mcommunity API Client

        Parameters
        ----------
        config : dict
            A dictionary of configuration options. Must contain,
            at minimum, 'client_id' and 'secret' keys.

        Returns
        -------
        None
        """

        self.logger = logging.getLogger(__name__)
        self.url_base = 'https://apigw.it.umich.edu/um'
        self.timeout = 10
        self.retries = 5
        self.backoff_factor = 2

        if isinstance(config, dict):
            self.__dict__.update(config)

        self.scope = 'iamgroups'
        self.token_url = self.url_base + '/inst/oauth2/token'
        self.call_url = self.url_base + '/iamGroups'

        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        try:
            self._request_token()
        except KeyError:
            raise KeyError('Unable to get access token from API')

        self.headers = {
            'x-ibm-client-id': '{}'.format(self.client_id),
            'authorization': 'Bearer {}'.format(self.token),
            'accept': 'application/json'
        }

    def _request_token(self):
        data = {
            'grant_type': 'client_credentials',
            'scope': 'constituents'
        }

        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'accept': 'application/json'
        }

        url_append = '?grant_type=client_credentials&scope={}'.format(
            self.scope
        )
        url = self.token_url + url_append

        r = self.session.post(
            url,
            data=json.dumps(data),
            headers=headers,
            auth=(self.client_id, self.secret),
            timeout=self.timeout
        )

        self.token = r.json()['access_token']

    def _patient_get(self, endpoint):
        for x in range(int(self.retries)):
            r = self.session.get(
                url=self.call_url + endpoint,
                headers=self.headers,
                timeout=self.timeout
            )
            if r.status_code == requests.codes.ok:
                if r.json():
                    return r.json()
                else:
                    time.sleep(float(self.backoff_factor)**x)
                    continue
        else:
            return False

    def _validate_name(self, name):
        """Validate a given name against MCommunity standards

        Parameters
        ----------
        name : str
            The name to validate

        Returns
        -------
        boolean
            true or false, depending on validity status.
        """

        endpoint = self.call_url + '/isValidName/{}'.format(name)
        r = self.session.get(
            url=endpoint,
            headers=self.headers,
            timeout=self.timeout
        )

        if r.json()['valid']:
            return name
        elif not r.json()['valid']:
            return re.sub(r'[^\w-]|[_]', ' ', name).strip()
        else:
            raise ValueError(r.json()['error'][0]['message'])

    def _create_entity_ldap(self, name):
        """Create an LDAP string for a given object

        Parameters
        ---------
        name : str
            The name of the object

        Returns
        -------
        str
            An LDAP string representation of the object.
        """
        if '=' in name or '@' in name:
            return name.lower()

        name = self._validate_name(name)
        data = self._patient_get('/find/both/{}'.format(name))
        if data:
            for item in data:
                if item['person']:
                    if item['naming'].lower() == name.lower():
                        return item['dn'].lower()
                elif item['group']:
                    hname = re.sub('[\._]', ' ', name).lower()
                    if item['displayName'].lower() == hname:
                        return item['dn'].lower()
                    else:
                        encoded_dn = quote(item['dn'])
                        group = self._patient_get('/profile/dn/{}'.format(
                            encoded_dn
                        ))
                        if group:
                            if isinstance(group['group'][0]['aliases'], list):
                                names = group['group'][0]['aliases']
                                names.append(group['group'][0]['name'])
                            else:
                                names = [group['group'][0]['name']]
                            names = [x.lower() for x in names]
                            if hname in names:
                                return item['dn'].lower()
        raise Exception('Unable to find {} in Mcommunity'.format(name))

    def _apply_update(self, endpoint):
        """Generic update function

        Parameters
        ----------
        endpoint : str
            The API endpoint to POST data to

        Returns
        -------
        obj
            A Requests response object
        """
        endpoint = self.call_url + endpoint
        for x in range(int(self.retries)):
            r = self.session.post(
                url=endpoint,
                data=json.dumps(self.group_data),
                headers=self.headers,
                timeout=self.timeout
            )
            if r.status_code == requests.codes.ok:
                if r.json()['status'] == 'success':
                    return r
            else:
                time.sleep(float(self.backoff_factor)**x)
                continue
        else:
            raise Exception('{}: {}'.format(r.status_code, r.text))

    def fetch_group(self, name):
        """Fetch information for an mcommunity group

        Parameters
        ----------
        name : str
            The name of the mcommunity group to fetch data for

        Returns
        -------
        None
            Nothing returned; self.group_data is populated instead.
        """

        dn = self._create_entity_ldap(name)
        if dn:
            encoded_dn = quote(dn)
            endpoint = '{}/profile/dn/{}'.format(
                self.call_url,
                encoded_dn
            )
            r = self.session.get(
                url=endpoint,
                headers=self.headers,
                timeout=self.timeout
            )
            if r.status_code == requests.codes.ok:
                if 'umichgroup' in r.json()['group'][0]['objectClass']:
                    self.group_data = r.json()['group'][0]
                else:
                    raise ValueError('{} is not a group. Got [{}]'.format(
                        name,
                        ', '.join(r.json()['group'][0]['objectClass'])
                    ))
            else:
                raise Exception('{}: {}'.format(r.status_code, r.text))

    def fetch_person(self, name):
        """Fetch information about a user from mcommunity

        Parameters
        ----------
        name : str
            The uniqname of the user to fetch data for

        Returns
        -------
        dict
            A dict of user information
        """
        endpoint = self.call_url + '/find/person/{}'.format(name)
        r = self.session.get(
            url=endpoint,
            headers=self.headers,
            timeout=self.timeout
        )

        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise Exception('{}: {}'.format(r.status_code, r.text))

    def create_group(self, name):
        """Create a new mcommunity group

        Parameters
        ----------
        name : str
            The name of the mcommunity group to create

        Returns
        -------
        none
            Nothing returned. After creation, group is fetched.
        """

        name = self._validate_name(name)
        endpoint = self.call_url + '/create'
        data = {
            'name': name
        }

        self.session.post(
            url=endpoint,
            data=json.dumps(data),
            headers=self.headers,
            timeout=self.timeout
        )

    def delete_group(self, name):
        """Delete an mcommunity group

        Parameters
        ----------
        name : str
            The name of the group to delete

        Returns
        -------
        dict
            A dict of response information from the server.
        """

        dn = self._create_entity_ldap(name)
        encoded_dn = quote(dn)
        endpoint = self.call_url + '/delete/{}'.format(encoded_dn)
        r = self.session.get(
            url=endpoint,
            headers=self.headers,
            timeout=self.timeout
        )
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise Exception('{}: {}'.format(r.status_code, r.text))

    def renew_group(self, name):
        """Renew an mcommunity group

        Parameters
        ----------
        name : str
            The name of the group to renew

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        dn = self._create_entity_ldap(name)
        encoded_dn = quote(dn)
        endpoint = self.call_url + '/renew/{}'.format(encoded_dn)
        r = self.session.get(
            url=endpoint,
            headers=self.headers,
            timeout=self.timeout
        )

        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            raise Exception('{}: {}'.format(r.status_code, r.text))

    def reserve_group(self, name):
        """Reserve a new mcommunity group

        Parameters
        ----------
        name : str
            The name of the mcommunity group to reserve

        Returns
        -------
        none
            Nothing returned. After creation, group is fetched.
        """

        name = self._validate_name(name)
        endpoint = self.call_url + '/reserve'
        data = {
            'name': re.sub('[\._]', ' ', name)
        }

        for x in range(int(self.retries)):
            try:
                r = self.session.post(
                    url=endpoint,
                    data=json.dumps(data),
                    headers=self.headers,
                    timeout=self.timeout
                )
                break
            except requests.exceptions.Timeout:
                time.sleep(float(self.backoff_factor)**x)
                continue
        else:
            raise Exception('Group reservation timed out.')

        if r.status_code == requests.codes.ok:
            if r.json()['status'] == 'success':
                return r
        else:
            raise Exception('{}: {}'.format(r.status_code, r.text))

    def update_group_aliases(self, aliases):
        """Update mcommunity group aliases

        Parameters
        ----------
        aliases : str, list
            A single alias, or a list thereof.

        Returns
        -------
        dict
            A dict of response information from the server.
        """

        if not isinstance(aliases, list):
            aliases = [aliases]

        for alias in aliases:
            clean_alias = self._validate_name(alias)
            if self.group_data['aliases']:
                self.group_data['aliases'].append(clean_alias)
            else:
                self.group_data['aliases'] = [clean_alias]

        return self._apply_update('/update/aliases')

    def update_group_description(self, description):
        """Update mcommunity group description

        Parameters
        ----------
        description : str
            A description to apply to the group.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        self.group_data['description'] = str(description)
        return self._apply_update('/update/description')

    def update_group_notice(self, notice):
        """Update mcommunity group notice

        Parameters
        ----------
        notice : str
            A notice to apply to the group.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        self.group_data['notice'] = str(notice)
        return self._apply_update('/update/notice')

    def update_group_links(self, links):
        """Update mcommunity group external links

        Parameters
        ----------
        links : str, tuple, list
            A single HTTP link, a tuple of (name,uri), or a list of either.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(links, list):
            links = [links]

        if not self.group_data['labeledUri']:
            self.group_data['labeledUri'] = []

        for link in links:
            if isinstance(link, tuple):
                self.group_data['labeledUri'].append({
                    'urlLabel': link[0],
                    'urlValue': link[1]
                })
            else:
                self.group_data['labeledUri'].append({'urlValue': link})

        return self._apply_update('/update/links')

    def add_group_members(self, members):
        """Add members to an mcommunity group.

        Parameters
        ----------
        members : str, list
            A single uniqname, group name, or external member address, or
            a list containing any combination thereof.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(members, list):
            members = [members]

        members = [self._create_entity_ldap(x) for x in members]

        for member in members:
            if 'uid=' in member:
                if self.group_data['memberDn']:
                    self.group_data['memberDn'].append(member)
                else:
                    self.group_data['memberDn'] = [member]
            elif 'cn=' in member:
                if self.group_data['memberGroupDn']:
                    self.group_data['memberGroupDn'].append(member)
                else:
                    self.group_data['memberGroupDn'] = [member]
            elif '@' in member:
                if self.group_data['memberExternal']:
                    self.group_data['memberExternal'].append({'email': member})
                else:
                    self.group_data['memberExternal'] = [{'email': member}]

    def remove_group_members(self, members):
        """Remove members fron an mcommunity group.

        Parameters
        ----------
        members : str, list
            A single uniqname, group name, or external member address, or
            a list containing any combination thereof.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(members, list):
            members = [members]
        members = [self._create_entity_ldap(x) for x in members]

        purge_external = False
        for member in members:
            try:
                if 'uid=' in member:
                    self.group_data['memberDn'].remove(member)
                elif 'cn=' in member:
                    self.group_data['memberGroupDn'].remove(member)
                elif '@' in member:
                    purge_external = True
            except (ValueError, AttributeError):
                self.logger.warning(
                    'Unable to remove {} as member'.format(member)
                )
                pass

        if purge_external:
            for index, item in enumerate(self.group_data['memberExternal']):
                if item['email'] in members:
                    del(self.group_data['memberExternal'][index])

    def update_group_members(self):
        """Generic endpoint for updating members

        Parameters
        ----------
        none

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        endpoints = [
            '/update/member',
            '/update/groupMember',
            '/update/externalMember'
        ]

        results = []

        for endpoint in endpoints:
            r = self._apply_update(endpoint)
            results.append(r)

        return results

    def update_group_moderators(self, moderators):
        """Update mcommunity group moderators

        Parameters
        ----------
        links : str, tuple, list
            A single email address, a tuple of (name,address), or
            a list of either.

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(moderators, list):
            moderators = [moderators]

        if not self.group_data['moderator']:
            self.group_data['moderator'] = []

        for moderator in moderators:
            if isinstance(moderator, tuple):
                self.group_data['moderator'].append({
                    'name': moderator[0],
                    'email': moderator[1]
                })
            else:
                self.group_data['moderator'].append({'email': moderator})

        return self._apply_update('/update/moderator')

    def add_group_owners(self, owners):
        """Add mcommunity group owners

        Parameters
        ----------
        links : str, list
            A single owner user or group, or a list of a combination
            of either

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(owners, list):
            owners = [owners]

        for owner in owners:
            try:
                self.group_data['ownerDn'].append(
                    self._create_entity_ldap(owner)
                )
            except Exception:
                pass

    def remove_group_owners(self, owners):
        """Remove mcommunity group owners

        Parameters
        ----------
        links : str, list
            A single owner user or group, or a list of a combination
            of either

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        if not isinstance(owners, list):
            owners = [owners]
        owners = [self._create_entity_ldap(x) for x in owners]

        for owner in owners:
            try:
                self.group_data['ownerDn'].remove(owner)
            except ValueError:
                pass

    def update_group_owners(self):
        """Generic endpoint for updating owners

        Parameters
        ----------
        none

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        return self._apply_update('/update/owner')

    def update_group_settings(self):
        """Generic endpoint for updating the following settings:
            - isprivate
            - isjoinable
            - IsSpamBlocked
            - IsEmailableByMembersOnly
            - IsEmailWarningSuspended

        Attributes are updated manually, and function is run. Example:
        conn = fetch_group('testgroup')
        conn.group_data['isprivate'] = True
        conn.update_group_settings()

        Parameters
        ----------
        none

        Returns
        -------
        dict
            A dict of response information from the server.
        """
        return self._apply_update('/update/settings')
