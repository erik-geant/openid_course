import os

from pprint import pformat

from oic.oic import Client as OIDCClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from oic import rndstr
from oic.utils.http_util import Redirect
from oic.oic.message import AuthorizationResponse
from oic.oic.message import AccessTokenResponse
from oic.oic.message import OpenIDSchema


__author__ = 'regu0004'


class Client(object):
    # TODO specify the correct path
    ROOT_PATH = "/Users/reid/workspace/openid_course"
    # TODO specify the correct URL
    ISSUER = "http://localhost:8090/"
    OP_URI = "https://op1.test.inacademia.org"

    def __init__(self, client_metadata):
        self.client = OIDCClient(client_authn_method=CLIENT_AUTHN_METHOD)

        provider_info = self.client.provider_config(Client.OP_URI)

        args = {
            "redirect_uris": [Client.ISSUER + 'implicit_flow_callback'],
            "contacts": ["foo@example.com"]
        }

        self.client.register(
            provider_info["registration_endpoint"], **args)

    def authenticate(self, session):
        # Use the session object to store state between requests

        session["state"] = rndstr()
        session["nonce"] = rndstr()
        args = {
            "client_id": self.client.client_id,
            "response_type": ["id_token", "token"],
            "scope": ["openid"],
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": self.client.registration_response["redirect_uris"][0]
        }
        auth_req = self.client.construct_AuthorizationRequest(request_args=args)
        login_url = auth_req.request(self.client.authorization_endpoint)
        return [login_url]

    def code_flow_callback(self, auth_response, session):

        # response = environ["QUERY_STRING"]

        arsp = self.client.parse_response(
            AuthorizationResponse,
            info=auth_response,
            sformat="urlencoded")

        assert arsp["state"] == session["state"]

        args = {
            "code": arsp["code"]
        }

        trsp = self.client.do_access_token_request(
            state=arsp["state"],
            request_args=args,
            authn_method="client_secret_basic")

        assert isinstance(trsp, AccessTokenResponse)
        # TODO validate the ID Token according to the OpenID Connect spec (sec 3.1.3.7.)

        # TODO make userinfo request
        userinfo = self.client.do_user_info_request(state=arsp["state"])
        assert isinstance(userinfo, OpenIDSchema)

        # TODO set the appropriate values
        access_code = arsp["code"]
        access_token = trsp["access_token"]
        id_token_claims = trsp["id_token"]
        return success_page(access_code, access_token, id_token_claims, userinfo)

    def implicit_flow_callback(self, auth_response, session):
        arsp = self.client.parse_response(
            AuthorizationResponse,
            info=auth_response,
            sformat="urlencoded")

        assert arsp["state"] == self.client.state

        # TODO validate the ID Token according to the OpenID Connect spec (sec 3.2.2.11.)

        access_code = arsp["code"]
        access_token = arsp["access_token"]
        id_token_claims = arsp["id_token"]
        return success_page(access_code, access_token, id_token_claims, None)


def success_page(auth_code, access_token, id_token_claims, userinfo):
    html_page = read_from_file("success_page.html")
    return html_page.format(auth_code, access_token,
                            pformat(id_token_claims.to_dict()),
                            pformat(userinfo.to_dict()))


def read_from_file(path):
    full_path = os.path.join(Client.ROOT_PATH, path)
    with open(full_path, "r") as f:
        return f.read()
