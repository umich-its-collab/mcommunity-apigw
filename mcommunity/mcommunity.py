import hashlib
import requests
import json

from . import core
from time import sleep
from ldap3.utils.dn import parse_dn
from ldap3.core.exceptions import LDAPInvalidDnError
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from requests.exceptions import Timeout
from urllib.parse import quote


class MCommSession(requests.Session):

    def __init__(self, client_id, secret, environment='prod', **kwargs):
        super(MCommSession, self).__init__(**kwargs)
        if environment == 'prod':
            url_base = 'https://gw.api.it.umich.edu/um'
        else:
            url_base = f'https://gw-{environment}.api.it.umich.edu/um'
        token_url = f'{url_base}/oauth2/token?grant_type=client_credentials&scope=iamgroups'
        self.call_url = url_base + '/iamGroups'

        self.session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )

        self.headers.update({
            'accept': 'application/json'
        })

        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

        try:
            self._request_token(token_url, client_id, secret)
        except KeyError:
            raise KeyError('Unable to get access token from API')

        self.headers.update({
            'authorization': 'Bearer {}'.format(self.token),
        })

    def _request_token(self, token_url, client_id, secret):
        """Request a token from the MCommunity API

        Parameters
        ----------
        token_url : string
        client_id : string
        secret : string

        Returns
        -------
        None
        """

        r = self.post(
            token_url,
            data=json.dumps({
                'grant_type': 'client_credentials',
                'scope': 'constituents'
            }),
            auth=(client_id, secret)
        )
        print(r.json())
        self.token = r.json()['access_token']

    def request(self, method, url, **kwargs):
        """Patched version of requests.Session.request with magic

        Parameters
        ----------
        method : string
        url : string

        Returns
        -------
        obj : A magic request object
        """

        if not url.lower().startswith('http'):
            url = ''.join([self.call_url, url])
        return super(MCommSession, self).request(method, url, **kwargs)


class MCommGroup:

    def __init__(self, client, name):
        self.client = client
        self.name = name
        self.fetch()

    @property
    def exists(self):
        return bool(self.dn)

    @property
    def expandedMembers(self):
        if not hasattr(self, '_expandedMembers'):
            groups = set([self.name])
            processed = set()
            members = set()
            while groups != processed:
                for group in groups.difference(processed):
                    processed.add(group)
                    _group = MCommGroup(self.client, group)
                    groups.update(_group.memberGroups)
                    members.update(_group.members)
            self._expandedMembers = list(members)
        return self._expandedMembers

    @property
    def externalMembers(self):
        if not hasattr(self, '_externalMembers'):
            self._externalMembers = [x['dn'] for x in self.memberExternal]
        return self._externalMembers

    @property
    def links(self):
        if not hasattr(self, '_links'):
            self._links = [x['labeledUri'] for x in self.urlLinks]
        return self._links

    @property
    def members(self):
        if not hasattr(self, '_members'):
            self._members = [parse_dn(x)[0][1] for x in self.memberDn]
        return self._members

    @property
    def memberGroups(self):
        if not hasattr(self, '_memberGroups'):
            self._memberGroups = [
                parse_dn(x)[0][1] for x in self.memberGroupDn
            ]
        return self._memberGroups

    @property
    def moderators(self):
        if not hasattr(self, '_moderators'):
            self._moderators = [x['dn'] for x in self.moderator]
        return self._moderators

    @property
    def owners(self):
        if not hasattr(self, '_owners'):
            self._owners = [parse_dn(x)[0][1] for x in self.ownerDn]
        return self._owners

    def fetch(self, targets=None):
        """Fetch information for an mcommunity group

        Parameters
        ----------
        targets : list
            Only fetch new data for attributes in this list

        Returns
        -------
        None
        """

        try:
            self.dn = core.get_entity_dn(self.client, self.name)
        except core.MCommEntityNotFound:
            self.dn = None

        if not self.dn:
            return

        # Updated data isn't always available immediately, so try to loop
        # for a bit if we don't see any change.
        # FIXME: people might call fetch when there actually haven't been any
        # changes, so this should probably be controlled by a flag.
        for i in range(5):
            r = self.client.get(
                url='/profile/dn/{}'.format(quote(self.dn))
            )
            if not r.ok:
                raise core.MCommError('{}: {}'.format(
                        r.status_code,
                        r.text,
                    )
                )

            group = r.json()['group'][0]
            group['owners_details'] = group.pop('owners')
            new_hash = hashlib.md5(
                json.dumps(group, sort_keys=True).encode('utf-8')
            )
            new_hash = new_hash.hexdigest()
            if getattr(self, 'group_hash', None) != new_hash:
                self.group_hash = new_hash
                break

            if i < 4:
                sleep(2**i)

        if not getattr(self, 'group_hash', None):
            raise core.MCommError('Unable to fetch fresh group data')

        group['objectClass'] = [x.lower() for x in group['objectClass']]
        if 'umichgroup' not in group['objectClass']:
            raise core.MCommError(
                    'Entity found is {}, not group'.format(
                        ', '.join(group['objectClass'])
                    )
                )

        if targets:
            for target in targets:
                setattr(self, target, group[target])
        else:
            self.__dict__.update(group)

        # Make sure that our list attrs are at least empty lists
        for attr in [
            'memberDn',
            'memberExternal',
            'memberGroupDn',
            'moderator',
            'ownerDn',
            'urlLinks',
        ]:
            if not getattr(self, attr, None):
                setattr(self, attr, [])

    def create(self):
        """Create a new mcommunity group

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        core.validate_name(self.client, self.name)

        # Testing shows that this is a black hole.
        # We should expect this to time out, and move on.
        try:
            self.client.post(
                url='/create',
                data=json.dumps({'name': self.name}),
            )
        except Timeout:
            pass

        self.fetch()
        return self

    def delete(self):
        """Delete an mcommunity group

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        r = self.client.get(
            url='/delete/{}'.format(quote(self.dn))
        )

        if r.ok:
            self.fetch()
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def renew(self):
        """Renew an mcommunity group

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        r = self.client.get(
            url='/renew/{}'.format(quote(self.dn))
        )

        if r.ok:
            self.fetch()
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def reserve(self):
        """Reserve a new mcommunity group

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        core.validate_name(self.client, self.name)
        # Testing shows that this is a black hole.
        # We should expect this to time out, and move on.
        try:
            self.client.post(
                url='/reserve',
                data=json.dumps({'name': self.name}),
                timeout=5
            )
        except Timeout:
            pass

        self.fetch()
        return self

    def update_aliases(self):
        """Update mcommunity group aliases

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        r = self.client.post(
            url='/update/aliases',
            data=json.dumps({
                'dn': self.dn,
                'aliases': self.aliases
            })
        )
        if r.ok:
            self.fetch(['aliases'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_description(self):
        """Update mcommunity group description

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        _valid_levels = ['PUBLIC', 'PROTECTED', 'PRIVATE']
        if self.descriptionLevel.upper() not in _valid_levels:
            raise core.MCommError('Invalid description level. Valid options '
                                  'are PUBLIC, PROTECTED, and PRIVATE.')
        r = self.client.post(
            url='/update/description',
            data=json.dumps({
                'dn': self.dn,
                'description': self.description,
                'descriptionLevel': self.descriptionLevel.upper()
            })
        )
        if r.ok:
            self.fetch(['description', 'descriptionLevel'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_errors_to(self):
        """Update mcommunity errorsTo

        Uniqnames or dn/cns can be appeneded to self.errorsTo

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        for item in self.errorsTo:
            try:
                parse_dn(item)
            except LDAPInvalidDnError:
                _index = self.errorsTo.index(item)
                dn = core.get_entity_dn(self.client, item)
                self.errorsTo[_index] = dn

        r = self.client.post(
            url='/update/errorsTo',
            data=json.dumps({
                'dn': self.dn,
                'errorsTo': self.errorsTo
            })
        )
        if r.ok:
            self.fetch(['errorsTo'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_errors_to_external(self):
        """Update mcommunity errorsToExternal

        Addresses can be added to self.errorsToExternal in these formats:

        str : user@domain.tld
        str : Test User <user@domain.tld>
        dict : {'name': 'Test User', 'email': 'user@domain.tld'}

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        for item in self.errorsToExternal:
            if not isinstance(item, dict):
                _index = self.errorsToExternal.index(item)
                self.errorsToExternal[_index] = {'email': item}

        r = self.client.post(
            url='/update/errorsToExternalMember',
            data=json.dumps({
                'dn': self.dn,
                'errorsToExternal': self.errorsToExternal
            })
        )
        if r.ok:
            self.fetch(['errorsToExternal', 'errorsToExternalRaw'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_external_members(self):
        """Update mcommunity group external members

        External members can be added to self.externalMembers in these formats:

        str : user@domain.tld
        str : Test User <user@domain.tld>
        dict : {'name': 'Test User', 'email': 'user@domain.tld'}

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.memberExternal = []
        for member in self.externalMembers:
            if isinstance(member, dict):
                self.memberExternal.append(member)
            else:
                self.memberExternal.append({'email': member})

        r = self.client.post(
            url='/update/externalMember',
            data=json.dumps({
                'dn': self.dn,
                'memberExternal': self.memberExternal
            })
        )
        if r.ok:
            del(self._externalMembers)
            self.fetch(['memberExternal', 'memberExternalRaw'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_links(self):
        """Update mcommunity group external links

        Links can be added to self.links in these formats:
        str : https://www.google.com
        str : Google https://www.google.com
        str : https://www.google.com Google
        dict: {'urlName' : 'Google', 'urlValue': 'https://www.google.com'}

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.urlLinks = []
        for item in self.links:
            if isinstance(item, dict):
                link = '{} {}'.format(
                    item['urlValue'],
                    item['urlName']
                )
            elif ' ' in item:
                _split = item.split(' ')
                for part in _split:
                    if 'http:' in part or 'https:' in part:
                        _url = _split.pop(_split.index(part))
                        break
                link = '{} {}'.format(_url, ' '.join(_split))
                _url = ''
            else:
                link = item

            self.urlLinks.append({'labeledUri': link})

        r = self.client.post(
            url='/update/links',
            data=json.dumps({
                'dn': self.dn,
                'urlLinks': self.urlLinks
            })
        )
        if r.ok:
            del(self._links)
            self.fetch(['urlLinks', 'labeledUri'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_membership(self):
        """Shortcut for updating all membership types at onces

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        if self.memberDn or self.members:
            self.members
            self.update_members()
        if self.memberGroupDn or self.memberGroups:
            self.memberGroups
            self.update_member_groups()
        if self.memberExternal or self.externalMembers:
            self.externalMembers
            self.update_external_members()

    def update_members(self):
        """Update members of an mcommunity group.

        Group members should be added to self.members by uniqname.
        However, using an ldap string should work, too.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.memberDn = []
        for member in self.members:
            self.memberDn.append(core.get_entity_dn(
                self.client,
                member
                )
            )

        r = self.client.post(
            url='/update/member',
            data=json.dumps({
                'dn': self.dn,
                'memberDn': self.memberDn
            })
        )
        if r.ok:
            del(self._members)
            self.fetch(['memberDn'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_member_groups(self):
        """Update member groups of an mcommunity group.

        Groups can be added to self.memberGroups by dn or cn.
        However, full ldap strings should work here as well.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.memberGroupDn = []
        for member in self.memberGroups:
            self.memberGroupDn.append(core.get_entity_dn(
                self.client,
                member
                )
            )
        r = self.client.post(
            url='/update/groupMember',
            data=json.dumps({
                'dn': self.dn,
                'memberGroupDn': self.memberGroupDn
            })
        )
        if r.ok:
            del(self._memberGroups)
            if hasattr(self, '_expandedMembers'):
                del(self._expandedMembers)
            self.fetch(['memberGroupDn', 'groupMemberDnRaw'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_moderators(self):
        """Update mcommunity group moderators

        Moderators can be added to self.externalMembers in these formats:

        str : user@domain.tld
        str : Test User <user@domain.tld>
        dict : {'name': 'Test User', 'email': 'user@domain.tld'}

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.moderator = []
        for mod in self.moderators:
            if isinstance(mod, dict):
                self.moderator.append(mod)
            else:
                self.moderator.append({'email': mod})

        r = self.client.post(
            url='/update/moderator',
            data=json.dumps({
                'dn': self.dn,
                'moderator': self.moderator
            })
        )

        if r.ok:
            del(self._moderators)
            self.fetch(['moderator', 'moderatorRaw'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_notice(self):
        """Update mcommunity group notice

        Parameters
        ----------
        None

        Returns
        -------
        Notice
        """

        _valid_levels = ['PUBLIC', 'PROTECTED', 'PRIVATE']
        if self.noticeLevel.upper() not in _valid_levels:
            raise core.MCommError('Invalid notice level. Valid options are '
                                  'PUBLIC, PROTECTED, and PRIVATE.')

        r = self.client.post(
            url='/update/notice',
            data=json.dumps({
                'dn': self.dn,
                'notice': self.notice,
                'noticeLevel': self.noticeLevel.upper()
            })
        )
        if r.ok:
            self.fetch(['notice', 'noticeLevel'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_ownership(self):
        """Alias function for update_owners

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.update_owners()

    def update_owners(self):
        """Update owners of an mcommunity group.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        self.ownerDn = []
        for owner in self.owners:
            self.ownerDn.append(core.get_entity_dn(
                self.client,
                owner
                )
            )

        r = self.client.post(
            url='/update/owner',
            data=json.dumps({
                'dn': self.dn,
                'ownerDn': self.ownerDn
            })
        )
        if r.ok:
            del(self._owners)
            self.fetch(['ownerDn', 'owners_details'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_request_to(self):
        """Update mcommunity requestTo

        Uniqnames or dn/cns can be appeneded to self.requestTo

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        for item in self.requestTo:
            try:
                parse_dn(item)
            except LDAPInvalidDnError:
                _index = self.requestTo.index(item)
                dn = core.get_entity_dn(self.client, item)
                self.requestTo[_index] = dn

        r = self.client.post(
            url='/update/requestTo',
            data=json.dumps({
                'dn': self.dn,
                'requestTo': self.requestTo
            })
        )
        if r.ok:
            self.fetch(['requestTo'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_request_to_external(self):
        """Update mcommunity requestToExternal

        Addresses can be added to self.requestToExternal in these formats:

        str : user@domain.tld
        str : Test User <user@domain.tld>
        dict : {'name': 'Test User', 'email': 'user@domain.tld'}

        Parameters
        ----------
            none

        Returns
        -------
        dict
            A dict of response information from the server.
        """

        for item in self.requestToExternal:
            if not isinstance(item, dict):
                _index = self.requestToExternal.index(item)
                self.requestToExternal[_index] = {'email': item}

        r = self.client.post(
            url='/update/requestToExternalMember',
            data=json.dumps({
                'dn': self.dn,
                'requestToExternal': self.requestToExternal
            })
        )
        if r.ok:
            self.fetch(['requestToExternal', 'requestToExternalRaw'])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))

    def update_settings(self):
        """Generic endpoint for updating the following settings:
            - isPrivate
            - isJoinable
            - IsSpamBlocked
            - IsEmailableByMembersOnly
            - IsEmailWarningSuppressed

        Parameters
        ----------
        None

        Returns
        -------
        None
        """

        r = self.client.post(
            url='/update/settings',
            data=json.dumps({
                'dn': self.dn,
                'isPrivate': self.isPrivate,
                'isJoinable': self.isJoinable,
                'isSpamBlocked': self.isSpamBlocked,
                'isEmailableByMembersOnly': self.isEmailableByMembersOnly,
                'isEmailWarningSuppressed': self.isEmailWarningSuppressed
            })
        )
        if r.ok:
            self.fetch([
                'isPrivate',
                'isJoinable',
                'isSpamBlocked',
                'isEmailableByMembersOnly',
                'isEmailWarningSuppressed'
            ])
        else:
            raise core.MCommError('{}: {}'.format(r.status_code, r.text))


class MCommPerson:

    def __init__(self, client, uniqname):
        self.client = client
        self.uniqname = uniqname
        self.fetch()

    def fetch(self):
        """Fetch information about a user from mcommunity

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        r = self.client.get(
            url='/find/person/{}'.format(self.uniqname)
        )

        # The API returns a 200 here no matter what.
        # The best way to determine if there's data is
        # probably to just check the dumped text response.
        if r.text:
            self.__dict__.update(r.json())
        else:
            raise core.MCommError('No matching user found')


class MCommClient:

    def __init__(self, client_id, secret, environment='prod'):
        self.client = MCommSession(client_id, secret, environment)

    def group(self, groupname):
        return MCommGroup(self.client, groupname)

    def person(self, uniqname):
        return MCommPerson(self.client, uniqname)
