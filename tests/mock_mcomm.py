#!/usr/bin/env python
import json

from flask import Flask

app = Flask(__name__)

@app.route("/iamGroups/create", methods=['POST'])
@app.route("/iamGroups/delete/<dn>", methods=['GET'])
@app.route("/iamGroups/renew/<dn>", methods=['GET'])
@app.route("/iamGroups/reserve", methods=['POST'])
@app.route("/iamGroups/update/<attrib>", methods=['POST'])
def return_success(attrib=False, dn=False):
    return '{"status": "success"}'

@app.route("/iamGroups/profile/dn/<dn>", methods=['GET'])
def get_group(dn):
    return '{"group":[{"objectClass":["top","groupofnames","umichgroup","rfc822mailgroup","umichexpire","dirxml-entitlementrecipient","posixgroup","ndsloginproperties"],"dn":"cn=testgroup,ou=user groups,ou=groups,dc=umich,dc=edu","name":"testgroup","description":null,"aliases":["alias1","alias2","alias3"],"memberDn":["uid=testuser,ou=people,dc=umich,dc=edu"],"ownerDn":["uid=testuser,ou=people,dc=umich,dc=edu","cn=controller-group,ou=user groups,ou=groups,dc=umich,dc=edu"],"owners":[{"dn":"uid=testuser,ou=people,dc=umich,dc=edu","naming":"testuser","displayName":"Test Usersson","email":"testuser@umich.edu","displayTitle":"Application Operations System Administrator Senior","title":["Application Operations System Administrator Senior"],"affiliation":["ITS Infra Sys Application Ops - Faculty and Staff","ITS Infrastrc - Systems - Faculty and Staff"],"description":null,"member":false,"owner":false,"moderator":false,"person":true,"group":false,"external":false,"securityEquals":null,"groupMembership":null,"role":null}],"expiredDate":"02/05/2020","email":"testgroup","isSpamBlocked":true,"isEmailWarningSuppressed":true,"isJoinable":false,"externalSystems":["Box","Google"],"isPrivate":true,"isEmailableByMembersOnly":false,"xmlAssociations":null,"moderatorRaw":null,"moderator":null,"memberGroupDn":null,"groupMemberDnRaw":null,"memberExternalRaw":null,"memberExternal":null,"renewAuthority":null,"disabled":false,"disabledBy":null,"disabledMessage":null,"disabledDate":null,"purgeDate":null,"notice":null,"acl":null,"equivalentToMe":null,"descriptionLevel":"PUBLIC","noticeLevel":"PUBLIC","urlLevel":"PUBLIC","errorsTo":null,"errorsToExternalRaw":null,"errorsToExternal":null,"requestTo":null,"requestToExternalRaw":null,"requestToExternal":null,"gidNumber":"2280774","editable":false,"urlLinks":null,"labeledUri":null,"authenticatedUserRole":null,"authenticatedUserRoles":null,"renewable":true,"moderated":false}],"error":null}'

@app.route("/iamGroups/find/both/<name>", methods=['GET'])
def get_both(name):
    if name == 'testuser':
        return '[{"dn":"uid=testuser,ou=People,dc=umich,dc=edu","naming":"testuser","displayName":"Test Usersson","email":"testuser@umich.edu","displayTitle":"Application Operations System Administrator Senior","title":["Application Operations System Administrator Senior"],"affiliation":["ITS Infra Sys Application Ops - Faculty and Staff","ITS Infrastrc - Systems - Faculty and Staff"],"description":null,"member":false,"owner":false,"moderator":false,"person":true,"group":false,"external":false,"securityEquals":null,"groupMembership":null,"role":null},{"dn":"cn=testuser-group,ou=User Groups,ou=Groups,dc=umich,dc=edu","naming":null,"displayName":"testuser-group","email":null,"displayTitle":null,"title":null,"affiliation":null,"description":null,"member":false,"owner":false,"moderator":false,"person":false,"group":true,"external":false,"securityEquals":null,"groupMembership":null,"role":null},{"dn":"cn=testuser-dev,ou=User Groups,ou=Groups,dc=umich,dc=edu","naming":null,"displayName":"testuser-dev","email":null,"displayTitle":null,"title":null,"affiliation":null,"description":null,"member":false,"owner":false,"moderator":false,"person":false,"group":true,"external":false,"securityEquals":null,"groupMembership":null,"role":null},{"dn":"cn=test-testuser,ou=User Groups,ou=Groups,dc=umich,dc=edu","naming":null,"displayName":"test-testuser","email":null,"displayTitle":null,"title":null,"affiliation":null,"description":null,"member":false,"owner":false,"moderator":false,"person":false,"group":true,"external":false,"securityEquals":null,"groupMembership":null,"role":null}]'
    elif name == 'testuser2':
        return '[{"dn":"uid=testuser2,ou=People,dc=umich,dc=edu","naming":"testuser2","displayName":"Test Usersson Jr.","email":"testuser2@umich.edu","displayTitle":"Application Operations System Administrator Senior","title":["Application Operations System Administrator Senior"],"affiliation":["ITS Infra Sys Application Ops - Faculty and Staff","ITS Infrastrc - Systems - Faculty and Staff"],"description":null,"member":false,"owner":false,"moderator":false,"person":true,"group":false,"external":false,"securityEquals":null,"groupMembership":null,"role":null}]'
    elif name =='testgroup':
        return '[{"dn":"cn=testgroup,ou=User Groups,ou=Groups,dc=umich,dc=edu","naming":null,"displayName":"testgroup","email":null,"displayTitle":null,"title":null,"affiliation":null,"description":null,"member":false,"owner":false,"moderator":false,"person":false,"group":true,"external":false,"securityEquals":null,"groupMembership":null,"role":null}]'
    elif name =='testgroup2':
        return '[{"dn":"cn=testgroup2,ou=User Groups,ou=Groups,dc=umich,dc=edu","naming":null,"displayName":"testgroup2","email":null,"displayTitle":null,"title":null,"affiliation":null,"description":null,"member":false,"owner":false,"moderator":false,"person":false,"group":true,"external":false,"securityEquals":null,"groupMembership":null,"role":null}]'
    else:
        return {}

@app.route("/iamGroups/find/person/<uid>", methods=['GET'])
def get_user(uid):
    return '{"dn":"uid=testuser,ou=People,dc=umich,dc=edu","naming":"testuser","displayName":"Test Usersson","email":"testuser@umich.edu","displayTitle":"Application Operations System Administrator Senior","title":["Application Operations System Administrator Senior"],"affiliation":["ITS Infra Sys Application Ops - Faculty and Staff","ITS Infrastrc - Systems - Faculty and Staff"],"description":null,"member":false,"owner":false,"moderator":false,"person":true,"group":false,"external":false,"securityEquals":null,"groupMembership":null,"role":null}'

@app.route("/iamGroups/isValidName/<name>", methods=['GET'])
def is_valid_name(name):
    if name != 'badname':
        return '{"valid": "true"}'
    else:
        return '{"valid": "false"}'

@app.route("/inst/oauth2/token", methods=['POST'])
def return_token():
    return '{"access_token": "a1b2c3d4c5d6e7f8g9h10i11j12k13l14"}'
