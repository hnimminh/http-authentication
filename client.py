import traceback
import requests
import json
import random
import uuid
import re
import base64
import hashlib
from auth_server import USERS, logger


def parse_scheme(_challenge):
    scheme_pattern = re.compile('(\w+) .+')
    return scheme_pattern.findall(_challenge)[0]


def random_choice(users):
    username = random.choice([key for key in users])
    password = users[username]

    return username, password


def gen_basic_credential(username, password):
    return 'Basic {}'.format(base64.b64encode(username + ':' + password))


class DigestAuthorization:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.txnids = {}
        self.digest_challenge = {}

    def _parse_challenge(self, _challenge):
        digest_challenge_pattern = re.compile('([^", ]+) ?[=] ?"?([^", ]+)"?')
        self.digest_challenge = dict(digest_challenge_pattern.findall(_challenge))

    @staticmethod
    def _H(data, algorithm):
        h = hashlib.md5(data).hexdigest()
        if algorithm =



def gen_digest_credential(method, uri, username, password, digest_challenge, entity_body):
    nonce = digest_challenge.get('nonce')
    realm = digest_challenge.get('realm')

    auth = DigestAuthentication({username: password}, realm)
    auth.txnids[nonce] = {'data': digest_challenge}

    digest_challenge.update({'uri': uri, 'cnonce': uuid.uuid4().hex, 'nc': '0000001', 'response': 'response'})
    _, response = auth.authenticate(method, digest_challenge, entity_body)

    return response


def main():
    try:
        server = "http://127.0.0.1:8088"
        path = '/testing'
        headers = {'Content-Type': 'application/json'}
        payload = json.dumps({"data": "test authentication"})
        method = 'GET'

        r1st = requests.request(method, server + path, headers=headers, data=payload)
        _body = r1st.text
        _status = r1st.status_code
        _headers = r1st.headers
        logger([_status, _headers, _body])

        if _status in [401, 407]:
            server_mode = {
                401: {'challenge': 'www-authenticate',
                      'credentials': 'authorization'},
                407: {'challenge': 'proxy-authenticate',
                      'credentials': 'proxy-authorization'}
            }

            challenge = _headers[server_mode[_status]['challenge']]
            scheme, digest_challenge = parse_challenge(challenge)

            username, password = random_choice(USERS)

            credentials = 'no-scheme'
            if scheme == 'Basic':
                credentials = gen_basic_credential(username, password)
            if scheme == 'Digest':
                credentials = gen_digest_credential('GET', path, username, password, digest_challenge, payload)

            headers[server_mode[_status]['credentials']] = credentials
            logger(credentials)

            r2nd = requests.request(method, server + path, headers=headers, data=payload)
            logger((r2nd.text, r2nd.status_code, r2nd.headers))

    except Exception as e:
        logger('{} | {}'.format(e, traceback.format_exc()))


if __name__ == '__main__':
    main()

