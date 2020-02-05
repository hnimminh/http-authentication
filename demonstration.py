#!/usr/bin/python
#
# https://tools.ietf.org/html/rfc2617
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

domain = 'github.com'
users = {'admin': 'admin@github', 'minh': 'nguyen-hoang-minh@github'}


def logger(message):
    print(message)


class BasicAuth:
    def __init__(self, credentials, realm):
        self.realm = realm
        self.secrets = []
        for username, password in credentials.items():
            self.secrets.append(base64.b64encode(username + ':' + password))

    def gen_www_auth_header(self):
        return 'Basic realm="{}"'.format(self.realm)

    def authenticate(self, auth_header):
        # auth_header = 'Basic <secret>'
        if auth_header[6:] in self.secrets:
            return True
        else:
            return False


class DigestAuth:
    def __init__(self, credentials, realm):
        self.credentials = credentials
        self.realm = realm
        self.txnids = {}
        self.client_auth_params = {}

    def gen_www_auth_header(self):
        # challenge = "Digest" (realm|[ domain ]|nonce|[opaque]|[stale]|[algorithm]|[qop-options]|[auth-param])

        # generate params for www_auth_header
        nonce = uuid.uuid4().hex
        qop = random.choice(['auth', 'auth-int'])
        algorithm = random.choice(['', 'MD5', 'MD5-sess'])

        # store nonce data per txn
        current, ttl = int(time.time()), 12
        nonce_data = {'qop': qop, 'algorithm': algorithm}
        self.txnids[nonce] = {'expire': current + ttl, 'data': nonce_data}

        # refresh txinids
        for txnid in self.txnids:
            if self.txnids[txnid]['expire'] < current:
                self.txnids.pop(txnid, None)

        # return www_auth_header
        www_auth_header = 'Digest realm="{}", nonce="{}"'.format(self.realm, nonce)
        for key, value in nonce_data.items():
            if value:
                www_auth_header += ', {}="{}"'.format(key, value)

        return www_auth_header

    def _parse_auth_header(self, _client_auth_header):
        auth_header_pattern = re.compile('([^", ]+) ?[=] ?"?([^", ]+)"?')
        self.client_auth_params = dict(auth_header_pattern.findall(_client_auth_header))

    @staticmethod
    def _H(data):
        # H(data) = MD5(data)
        return hashlib.md5(data).hexdigest()

    @staticmethod
    def _KD(secret, data):
        # KD(secret, data) = H(concat(secret, ":", data))
        return hashlib.md5(secret + ':' + data).hexdigest()

    def _A1(self, username, password, nonce, cnonce, algorithm):
        # If the "algorithm" directive's value is "MD5" or is unspecified, then A1 is:
        # A1 = unq(username-value) ":" unq(realm-value) ":" passwd
        # If the "algorithm" directive's value is "MD5-sess"
        # A1 = H( unq(username-value) ":" unq(realm-value) ":" passwd ) ":" unq(nonce-value) ":" unq(cnonce-value)
        # where passwd   = < user's password >

        a1 = username + ':' + self.realm + ':' + password
        if algorithm == 'MD5-sess':
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

    def authenticate(self, method, auth_header, entity_body):
        result = False
        try:
            self._parse_auth_header(auth_header)
            _username = self.client_auth_params.get('username')
            _nonce = self.client_auth_params.get('nonce')
            _realm = self.client_auth_params.get('realm')
            _algorithm = self.client_auth_params.get('algorithm', '')
            _cnonce = self.client_auth_params.get('cnonce')
            _uri = self.client_auth_params.get('uri')
            _nc = self.client_auth_params.get('nc')
            _qop = self.client_auth_params.get('qop')
            _response = self.client_auth_params.get('response')

            if _username and _realm and _nonce and _cnonce and _uri and _nc and _qop and _response:
                if _nonce in self.txnids:
                    qop = self.txnids[_nonce]['data']['qop']
                    algorithm = self.txnids[_nonce]['data']['algorithm']
                    if _realm == self.realm and _qop == qop and _algorithm == algorithm:
                        if _username in self.credentials:
                            password = self.credentials[_username]
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
                            print(response + '|' + _response)
                            if response == _response:
                                result = True
            # clear nonce
            self.txnids.pop(_nonce, None)
        finally:
            return result


http_auth = DigestAuth(users, domain)


class Server:
    def __init__(self):
        """ initial variable, get module name and start"""
        logger("Start HTTP Server")

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

            authorization_header = req.get_header('AUTHORIZATION')
            logger(authorization_header)

            if authorization_header:
                response = http_auth.authenticate(request_method, authorization_header, request_body)

                if response:
                    status = falcon.HTTP_200
                else:
                    status = falcon.HTTP_403

            else:
                digest_auth_header = http_auth.gen_www_auth_header()
                resp.set_header('WWW-Authenticate', digest_auth_header)
                logger(digest_auth_header)

                status = falcon.HTTP_401
                response = 'failure'

            logger('RESPONSE [{}] {}'.format(resp.status, resp.body))

        except Exception as e:
            logger('{} | {}'.format(e, traceback.format_exc()))
            status = falcon.HTTP_500
            response = 'failure'
        finally:
            resp.content_type = 'application/json'
            resp.status = status
            resp.body = json.dumps({'ack': response}).encode('utf-8')


##################################################################################

api = application = falcon.API()
api.add_sink(Server(), r'/*')

if __name__ == '__main__':
    httpd = make_server('0.0.0.0', 8088, api)
    httpd.serve_forever()
