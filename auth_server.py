#!/usr/bin/python
#
# HTTP Authentication: Basic and Digest Access Authentication
# SIP challenge-based mechanism for authentication that is based on authentication in HTTP
#
import traceback
import falcon
import json
import uuid
import time
import re
import base64
import hashlib
import random
from wsgiref.simple_server import make_server


DOMAIN = 'github.com'
USERS = {'admin': 'admin@github', 'minh': 'nguyen-hoang-minh@github'}

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = 8088


def logger(message):
    print(message)


class BasicAuthentication:
    def __init__(self, users, realm):
        self.realm = realm
        self.secrets = []
        for username, password in users.items():
            self.secrets.append(base64.b64encode(username + ':' + password))

    def gen_challenge(self):
        return 'Basic realm="{}"'.format(self.realm)

    def authenticate(self, credentials):
        # auth_header = 'Basic <secret>'
        result = False, None
        try:
            if credentials[6:] in self.secrets:
                result = True, credentials[6:]
        except Exception as e:
            logger([e, traceback.format_exc()])
        finally:
            return result


class DigestAuthentication:
    def __init__(self, users, realm):
        self.users = users
        self.realm = realm
        self.txnids = {}
        self.digest_credentials = {}

    def gen_challenge(self):
        # challenge = "Digest (realm|[domain]|nonce|[opaque]|[stale]|[algorithm]|[qop]|[auth-param])"
        current, ttl = int(time.time()), 60
        # refresh txinids
        for txnid in [key for key in self.txnids]:
            if self.txnids[txnid]['expire'] < current:
                self.txnids.pop(txnid, None)

        # generate params for www_auth_header
        nonce = base64.b64encode(self.realm + uuid.uuid4().hex)
        qop = random.choice(['', 'auth', 'auth-int'])
        algorithm = random.choice(['', 'MD5', 'MD5-sess'])          # RFC7616 (SHA256, SHA256-sess)

        # store nonce data per txn
        nonce_data = {'qop': qop, 'algorithm': algorithm}
        self.txnids[nonce] = {'expire': current + ttl, 'data': nonce_data}

        # return challenge
        challenge = 'Digest realm="{}", nonce="{}"'.format(self.realm, nonce)
        for key, value in nonce_data.items():
            if value:
                challenge += ', {}="{}"'.format(key, value)

        return challenge

    def _parse_credentials(self, _credentials):
        _credentials_pattern = re.compile('([^", ]+) ?[=] ?"?([^", ]+)"?')
        self.digest_credentials = dict(_credentials_pattern.findall(_credentials))

    @staticmethod
    def _H(data):
        # H(data) = MD5(data)
        return hashlib.md5(data).hexdigest()

    def _KD(self, secret, data):
        # KD(secret, data) = H(concat(secret, ":", data))
        return self._H(secret + ':' + data)

    def _A1(self, username, password, nonce, cnonce, algorithm):
        # If the "algorithm" directive's value is "MD5" or is unspecified, then A1 is:
        # A1 = unq(username-value) ":" unq(realm-value) ":" passwd
        # If the "algorithm" directive's value is "MD5-sess"
        # A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd ) ":" unq(nonce-value) ":" unq(cnonce-value)
        # where passwd   = < user's password >

        a1 = username + ':' + self.realm + ':' + password
        if algorithm[-5:] == '-sess':
            a1 = self._H(username + ':' + self.realm + ':' + password) + ':' + nonce + ':' + cnonce

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

    def authenticate(self, method, _credentials, entity_body):
        result = False, None
        try:
            self._parse_credentials(_credentials)
            _username = self.digest_credentials.get('username')
            _nonce = self.digest_credentials.get('nonce')
            _realm = self.digest_credentials.get('realm')
            _algorithm = self.digest_credentials.get('algorithm', '')
            _cnonce = self.digest_credentials.get('cnonce', '')
            _uri = self.digest_credentials.get('uri')
            _nc = self.digest_credentials.get('nc', '')
            _qop = self.digest_credentials.get('qop', '')
            _response = self.digest_credentials.get('response')

            if _username and _realm and _nonce and _uri and _response:
                if _nonce in self.txnids:
                    qop = self.txnids[_nonce]['data']['qop']
                    algorithm = self.txnids[_nonce]['data']['algorithm']
                    if _realm == self.realm and _qop == qop and _algorithm == algorithm:
                        if _username in self.users:
                            password = self.users[_username]
                            A1 = self._A1(_username, password, _nonce, _cnonce, _algorithm)
                            A2 = self._A2(qop, method, _uri, entity_body)

                            if _qop in ['auth', 'auth-int']:
                                response = self._KD(self._H(A1), _nonce +
                                                    ':' + _nc +
                                                    ':' + _cnonce +
                                                    ':' + _qop +
                                                    ':' + self._H(A2))
                            else:
                                response = self._KD(self._H(A1), _nonce + ':' + self._H(A2))
                            logger('compare 2 responses ' + response + '|' + _response)
                            if response == _response:
                                result = True, response
                                # clear nonce
                                self.txnids.pop(_nonce, None)
        except Exception as e:
            logger([e, traceback.format_exc()])
        finally:
            return result


class Server:
    def __init__(self, scheme='digest'):
        """ initial variable, get module name and start"""
        self.challenge_code = falcon.HTTP_401                   # 401 Unauthorized  | 407 Proxy Authentication Required
        self.challenge_header = 'WWW-Authenticate'              # WWW-Authenticate  | Proxy-Authenticate
        self.credentials_header = 'Authorization'               # Authorization     | Proxy-Authorization

        self.scheme = 'digest'
        if scheme.lower() in ['basic', 'digest']:
            self.scheme = scheme.lower()

        self.http_auth = DigestAuthentication(USERS, DOMAIN)
        if self.scheme == 'basic':
            self.http_auth = BasicAuthentication(USERS, DOMAIN)

    def __call__(self, req, resp):
        logger("-------------------------------------------------------------------------------------------------------------------------------------------------------------------")
        response = None
        status = falcon.HTTP_400

        try:
            request_method = req.method
            request_url = req.uri
            logger('REQUEST: {} {}'.format(request_method, request_url))

            request_headers = req.headers
            logger('HEADERS: {}'.format(request_headers))

            dict_request_params = req.params
            logger('PARAMS: {}'.format(dict_request_params))

            request_body = req.stream.read()
            logger('BODY: {}'.format(request_body))

            authorization_header = req.get_header(self.credentials_header)
            logger(authorization_header)

            if authorization_header:

                if self.scheme == 'basic':
                    verify, _ = self.http_auth.authenticate(authorization_header)
                else:
                    verify, _ = self.http_auth.authenticate(request_method, authorization_header, request_body)

                if verify:
                    status = falcon.HTTP_200
                else:
                    status = falcon.HTTP_403

            else:
                challenge_auth_header = self.http_auth.gen_challenge()
                resp.set_header(self.challenge_header, challenge_auth_header)
                logger(challenge_auth_header)

                status = self.challenge_code
                response = 'failure'

        except Exception as e:
            logger('{} | {}'.format(e, traceback.format_exc()))
            status = falcon.HTTP_500
            response = 'exception'
        finally:
            resp.content_type = 'application/json'
            resp.status = status
            resp.body = json.dumps({'ack': response}).encode('utf-8')

            logger('RESPONSE [{}] {}'.format(resp.status, resp.body))


##################################################################################

api = application = falcon.API()
api.add_sink(Server(), r'/*')

if __name__ == '__main__':
    logger("Start HTTP Server {}:{}".format(LISTEN_ADDR, LISTEN_PORT))
    httpd = make_server(LISTEN_ADDR, LISTEN_PORT, api)
    httpd.serve_forever()
