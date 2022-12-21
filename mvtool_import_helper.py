# coding: utf-8
#
# Copyright (C) 2022 Helmar Hutschenreuter
#
# MV-Tool Import Helper is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MV-Tool Import Helper is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with MV-Tool Import Helper. If not, see <http://www.gnu.org/licenses/>.

import json
import ssl
import urllib.parse
import urllib.request
from getpass import getpass


class Session:
    def __init__(self, server_url: str = "http://localhost:8000"):
        self.base_url = server_url + "/api"
        self.auth_url = server_url + "/auth/token"
        self.access_token = None

        # create a SSL context to ignore certificate errors
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def _json_encode(self, data: dict | list[dict]) -> bytes:
        return json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")

    def _json_decode(self, data: bytes) -> dict | list[dict]:
        return json.loads(data.decode("utf-8"))

    def _process_json_request(
        self, url: str, data: dict | list[dict] | None = None, method=None
    ) -> dict | list[dict] | None:
        # create a request
        url = self.base_url + url
        req = (
            urllib.request.Request(url, method=method)
            if data is None
            else urllib.request.Request(
                url, data=self._json_encode(data), method=method
            )
        )

        # add request headers
        req.add_header("Content-Type", "application/json")
        if self.access_token:
            req.add_header("Authorization", "Bearer " + self.access_token)

        # send request and return response
        with urllib.request.urlopen(req, context=self.ssl_context) as response:
            response_body = response.read()
            return self._json_decode(response_body) if response_body else None

    def authenticate(self):
        # send username and password to as oauth2 request
        username = input("Username: ")
        password = getpass("Password: ")

        # create a request
        form_data = urllib.parse.urlencode(
            {"username": username, "password": password, "grant_type": "password"}
        ).encode("utf-8")
        req = urllib.request.Request(self.auth_url, data=form_data)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        # send request and set access token
        with urllib.request.urlopen(req, context=self.ssl_context) as response:
            self.access_token = self._json_decode(response.read())["access_token"]
