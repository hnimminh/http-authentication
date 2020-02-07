import traceback
import requests
import json
import random
import re
import base64
import hashlib
import time

USERS = {'admin': 'admin@github'}


def logger(message):
    print(message)


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

    @staticmethod
    def _parse_challenge(_challenge):
        digest_challenge_pattern = re.compile('([^", ]+) ?[=] ?"?([^", ]+)"?')
        return dict(digest_challenge_pattern.findall(_challenge))

    @staticmethod
    def _H(data):
        return hashlib.md5(data).hexdigest()

    def _KD(self, secret, data):
        return self._H(secret + ':' + data)

    def _A1(self, realm, nonce, cnonce, algorithm):
        a1 = self.username + ':' + realm + ':' + self.password
        if algorithm[-5:] == '-sess':
            a1 = self._H(self.username + ':' + realm + ':' + self.password) + ':' + nonce + ':' + cnonce

        return a1

    def _A2(self, qop, method, uri, entity_body):
        a2 = method + ':' + uri
        if qop == 'auth-int':
            a2 = method + ':' + uri + ':' + self._H(entity_body)

        return a2

    def authorize(self, method, uri, _challenge, entity_body):
        current, ttl = int(time.time()), 60
        # refresh txinids
        for txnid in [key for key in self.txnids]:
            if self.txnids[txnid]['expire'] < current:
                self.txnids.pop(txnid, None)

        #
        digest_challenge = self._parse_challenge(_challenge)
        nonce = digest_challenge.get('nonce')
        realm = digest_challenge.get('realm')
        qop = digest_challenge.get('qop', '')
        algorithm = digest_challenge.get('algorithm', '')

        if nonce and realm:
            nonce_count = 1
            if nonce in self.txnids:
                nonce_count = self.txnids[nonce]['data']['nc'] + 1

            cnonce = base64.b64encode(str(current))
            nc = '0000000{}'.format(nonce_count)
            if not qop:
                cnonce, nc = '', ''

            A1 = self._A1(realm, nonce, cnonce, algorithm)
            A2 = self._A2(qop, method, uri, entity_body)

            if qop in ['auth', 'auth-int']:
                response = self._KD(self._H(A1), nonce +
                                    ':' + nc +
                                    ':' + cnonce +
                                    ':' + qop +
                                    ':' + self._H(A2))
            else:
                response = self._KD(self._H(A1), nonce + ':' + self._H(A2))

            digest_challenge.update({'username': self.username, 'cnonce': cnonce,
                                     'uri': uri, 'nc': nc, 'response': response})

            self.txnids[nonce] = {'expire': current + ttl, 'data': digest_challenge}

            # return credentials
            credentials = 'Digest username="{}"'.format(self.username)
            for key, value in digest_challenge.items():
                if value:
                    credentials += ', {}="{}"'.format(key, value)

            return credentials


def main():
    try:
        server = "http://127.0.0.1:8088"
        path = '/testing'
        headers = {'Content-Type': 'application/json'}
        payload = json.dumps({"data": "test authentication"})
        method = 'GET'

        username, password = random_choice(USERS)
        basic_credentials = gen_basic_credential(username, password)
        auth = DigestAuthorization(username, password)

        # first request
        r1st = requests.request(method, server + path, headers=headers, data=payload)
        _body = r1st.text
        _status = r1st.status_code
        _headers = r1st.headers
        logger([_status, _headers, _body])

        # authorize
        if _status in [401, 407]:
            server_mode = {
                401: {'challenge': 'www-authenticate',
                      'credentials': 'authorization'},
                407: {'challenge': 'proxy-authenticate',
                      'credentials': 'proxy-authorization'}
            }

            challenge = _headers[server_mode[_status]['challenge']]
            scheme = parse_scheme(challenge)

            credentials = 'no-scheme'
            if scheme == 'Basic':
                credentials = basic_credentials
            if scheme == 'Digest':
                credentials = auth.authorize(method, path, challenge, payload)

            headers[server_mode[_status]['credentials']] = credentials
            logger(credentials)

            r2nd = requests.request(method, server + path, headers=headers, data=payload)
            logger([r2nd.status_code, r2nd.headers, r2nd.text])

    except Exception as e:
        logger('{} | {}'.format(e, traceback.format_exc()))


if __name__ == '__main__':
    main()
