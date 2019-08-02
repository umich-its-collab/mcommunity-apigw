import mcommunity

config = {
    'client_id': '1234567890',
    'secret': '123abc-456def-789ghi',
    'url_base': 'http://localhost:5000'
}


def test_group_fetch(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    assert conn.group_data['name'] == 'testgroup'


def test_group_fetch_by_cn(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('alias1')
    assert conn.group_data['name'] == 'testgroup'


def test_person_fetch(mock_mcomm):
    conn = mcommunity.Client(config=config)
    person = conn.fetch_person('testuser')
    assert person['naming'] == 'testuser'


def test_group_creation(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.create_group('testgroup')


def test_group_reservation(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.reserve_group('testgroup')


def test_group_deletion(mock_mcomm):
    conn = mcommunity.Client(config=config)
    r = conn.delete_group('testgroup')
    assert r['status'] == 'success'


def test_group_renew(mock_mcomm):
    conn = mcommunity.Client(config=config)
    r = conn.renew_group('testgroup')
    assert r['status'] == 'success'


def test_group_update_aliases(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    conn.update_group_aliases('testalias')
    assert 'testalias' in conn.group_data['aliases']


def test_group_update_description(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    conn.update_group_description('test description')
    assert conn.group_data['description'] == 'test description'


def test_group_update_notice(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    conn.update_group_notice('test notice')
    assert conn.group_data['notice'] == 'test notice'


def test_group_update_links_labeled(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    links = ('Test Link', 'https://test.link')
    conn.update_group_links(links)
    assert conn.group_data['labeledUri'][0]['urlLabel'] == 'Test Link'
    assert conn.group_data['labeledUri'][0]['urlValue'] == 'https://test.link'


def test_group_update_links_plain(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    links = 'https://test.link'
    conn.update_group_links(links)
    assert conn.group_data['labeledUri'][0]['urlValue'] == 'https://test.link'


def test_group_owners_update(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    conn.add_group_owners('testuser2')
    conn.update_group_owners()
    testuser2 = conn._create_entity_ldap('testuser2')
    assert testuser2 in conn.group_data['ownerDn']
    conn.remove_group_owners('testuser2')
    conn.update_group_owners()
    assert testuser2 not in conn.group_data['ownerDn']


def test_group_members_update(mock_mcomm):
    conn = mcommunity.Client(config=config)
    conn.fetch_group('testgroup')
    members = [
        'testuser2',
        'testgroup2',
        'test@domain.tld'
    ]
    conn.add_group_members(members)
    conn.update_group_members()
    testuser2 = conn._create_entity_ldap('testuser2')
    testgroup2 = conn._create_entity_ldap('testgroup2')
    externalMember = 'test@domain.tld'
    assert testuser2 in conn.group_data['memberDn']
    assert testgroup2 in conn.group_data['memberGroupDn']
    assert conn.group_data['memberExternal'][0]['email'] == externalMember
    conn.remove_group_members(members)
    conn.update_group_members()
    assert testuser2 not in conn.group_data['memberDn']
    assert testgroup2 not in conn.group_data['memberGroupDn']
    assert not conn.group_data['memberExternal']
