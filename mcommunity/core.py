from urllib.parse import quote


def validate_name(client, name):
    """Validate a given name against the MCommunity API

    Parameters
    ----------
    client : obj
        An instance of mcommunity.MCommClient

    name : str
        The name to validate

    Returns
    -------
    boolean
        true or false, depending on validity status.
    """

    r = client.get('/isValidName/{}'.format(name)).json()

    if r['valid']:
        return True
    elif not r['valid']:
        raise MCommError(r['error'][0]['message'])


def get_entity_dn(client, name):
    """Fetch the DN for a specified entity in MCommunity

    Parameters
    ---------
    client : obj
        An instance of mcommunity.MCommClient

    name : str
        The name of the target entity

    Returns
    -------
    str
        The DN of the given entity
    """
    if '=' in name or '@' in name:
        return name

    data = client.get('/find/both/{}'.format(name)).json()

    if data:
        for item in data:
            if item['person']:
                if item['naming'].casefold() == name.casefold():
                    return item['dn']
            elif item['group']:
                if item['displayName'].casefold() == name:
                    return item['dn']
                else:
                    r = client.get('/profile/dn/{}'.format(
                        quote(item['dn'])
                    ))
                    if r.ok:
                        group = r.json()['group'][0]
                        aliases = group['aliases']
                        aliases.append(group['name'])
                        if name in [x.casefold() for x in aliases]:
                            return item['dn']


class MCommError(Exception):
    pass
