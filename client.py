import traceback
import requests
import json
import random
import uuid
import re
import base64
import hashlib

USERS = {'admin': 'admin@github1', 'minh1': 'nguyen-hoang-minh@github'}
MODE = {401: {'challenge': 'www-authenticate', 'credentials': 'authorization'},
        407: {'challenge': 'proxy-authenticate', 'credentials': 'proxy-authorization'}}


def logger(message):
    print(message)


class Authorization:
    def __init__(self, users):
        self.username = random.choice([key for key in users])
        self.password = users[self.username]
        self.scheme = None
        self.digest_challenge = None

    def _parse_challenge(self, _challenge):
        scheme_pattern = re.compile('(\w+) .+')
        self.scheme = scheme_pattern.findall(_challenge)[0]
        digest_challenge_pattern = re.compile('([^", ]+) ?[=] ?"?([^", ]+)"?')
        self.digest_challenge = dict(digest_challenge_pattern.findall(_challenge))

    def basic_credentials(self):
        return 'Basic {}'.format(base64.b64encode(self.username + ':' + self.password))

    @staticmethod
    def _H(data):
        # H(data) = MD5(data)
        return hashlib.md5(data).hexdigest()

    def _KD(self, secret, data):
        # KD(secret, data) = H(concat(secret, ":", data))
        return self._H(secret + ':' + data)

    def _A1(self, username, password, realm, nonce, cnonce, algorithm):
        # If the "algorithm" directive's value is "MD5" or is unspecified, then A1 is:
        # A1 = unq(username-value) ":" unq(realm-value) ":" passwd
        # If the "algorithm" directive's value is "MD5-sess"
        # A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd ) ":" unq(nonce-value) ":" unq(cnonce-value)
        # where passwd   = < user's password >

        a1 = username + ':' + realm + ':' + password
        if algorithm[-5:] == '-sess':
            a1 = self._H(username + ':' + realm + ':' + password) + ':' + nonce + ':' + cnonce

        return a1

    def _A2(self, qop, method, uri, entity_body):
        # If the "qop" directive's value is "auth" or is unspecified
        # A2 = Method ":" digest-uri-value
        # If the "qop" value is "auth-int", then A2 is:
        # A2 = Method ":" digest-uri-value ":" H(entity-body)
        a2 = method + ':' + uri
        if qop == 'auth-int':
            a2 = method + ':' + uri + ':' + self._H(entity_body)

        return a2

    def digest_credentials(self, method, uri, entity_body):
        nonce = self.digest_challenge.get('nonce')
        realm = self.digest_challenge.get('realm')
        algorithm = self.digest_challenge.get('algorithm')
        qop = self.digest_challenge.get('qop')

        cnonce = uuid.uuid4().hex
        nc = '0000001'

        A1 = self._A1(self.username, self.password, realm, nonce, cnonce, algorithm)
        A2 = self._A2(qop, method, uri, entity_body)

        if qop in ['auth', 'auth-int']:
            response = self._KD(self._H(A1), nonce +
                                ':' + nc +
                                ':' + cnonce +
                                ':' + qop +
                                ':' + self._H(A2))
        else:
            response = self._KD(self._H(A1), nonce + ':' + self._H(A2))

        digest_response = self.digest_challenge
        digest_response.update({'cnonce': cnonce, 'nc': nc, 'response': response, 'uri': uri})

        # return challenge
        credentials = 'Digest username="{}"'.format(self.username)
        for key, value in digest_response.items():
            if value:
                credentials += ', {}="{}"'.format(key, value)

        return credentials

    def authorize(self, method, uri, entity_body, _challenge):
        credentials = None
        try:
            self._parse_challenge(_challenge)
            logger([self.scheme, self.digest_challenge])

            if self.scheme == 'Basic':
                credentials = self.basic_credentials()
            elif self.scheme == 'Digest':
                credentials = self.digest_credentials(method, uri, entity_body)
            else:
                credentials = 'cai dit me'

        except Exception as e:
            logger([e, traceback.format_exc()])
        finally:
            return credentials


if __name__ == '__main__':
    server = "http://127.0.0.1:8088"
    path = '/testing'
    headers = {'Content-Type': 'application/json'}
    payload = json.dumps({"data": "test authentication"})

    r1st = requests.get(server+path, headers=headers, data=payload)
    _body = r1st.text
    _status = r1st.status_code
    _headers = r1st.headers
    logger([_status, _headers, _body])

    if _status in [401, 407]:
        challenge = _headers[MODE[_status]['challenge']]
        logger(challenge)
        auth = Authorization(USERS)

        credentials_header_name = MODE[_status]['credentials']
        credentials_header_value = auth.authorize('GET', path, payload, challenge)
        headers[credentials_header_name] = credentials_header_value

        logger(credentials_header_value)

        r2nd = requests.get(server+path, headers=headers, data=payload)

        logger((r2nd.text, r2nd.status_code, r2nd.headers))
