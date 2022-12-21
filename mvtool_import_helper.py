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

    def authenticate(self, username: str | None = None, password: str | None = None):
        # send username and password to as oauth2 request
        username = input("Username: ") if username is None else username
        password = getpass("Password: ") if password is None else password

        # create a request
        form_data = urllib.parse.urlencode(
            {"username": username, "password": password, "grant_type": "password"}
        ).encode("utf-8")
        req = urllib.request.Request(self.auth_url, data=form_data)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        # send request and set access token
        with urllib.request.urlopen(req, context=self.ssl_context) as response:
            self.access_token = self._json_decode(response.read())["access_token"]


class Catalogs:
    def __init__(self, session: Session):
        self.session = session

    def _get_catalogs_url(self, catalog_id: int | None = None) -> str:
        return "/catalogs" if catalog_id is None else "/catalogs/%d" % catalog_id

    def list_catalogs(self) -> list[dict]:
        return self.session._process_json_request(
            self._get_catalogs_url(), method="GET"
        )

    def create_catalog(self, catalog_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_catalogs_url(), catalog_data, method="POST"
        )

    def get_catalog(self, catalog_id) -> dict:
        return self.session._process_json_request(
            self._get_catalogs_url(catalog_id), method="GET"
        )

    def update_catalog(self, catalog_id, catalog_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_catalogs_url(catalog_id), catalog_data, method="PUT"
        )

    def delete_catalog(self, catalog_id):
        self.session._process_json_request(
            self._get_catalogs_url(catalog_id), method="DELETE"
        )


class CatalogModules:
    def __init__(self, session: Session):
        self.session = session

    def _get_catalog_modules_url(self, catalog_id: int) -> str:
        return "/catalogs/%d/catalog-modules" % catalog_id

    def _get_catalog_module_url(self, catalog_module_id: int) -> str:
        return "/catalog-modules/%d" % catalog_module_id

    def list_catalog_modules(self, catalog_id: int) -> list[dict]:
        return self.session._process_json_request(
            self._get_catalog_modules_url(catalog_id), method="GET"
        )

    def create_catalog_module(self, catalog_id: int, catalog_module_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_catalog_modules_url(catalog_id),
            catalog_module_data,
            method="POST",
        )

    def get_catalog_module(self, catalog_module_id: int) -> dict:
        return self.session._process_json_request(
            self._get_catalog_module_url(catalog_module_id), method="GET"
        )

    def update_catalog_module(
        self, catalog_module_id: int, catalog_module_data: dict
    ) -> dict:
        return self.session._process_json_request(
            self._get_catalog_module_url(catalog_module_id),
            catalog_module_data,
            method="PUT",
        )

    def delete_catalog_module(self, catalog_module_id: int):
        self.session._process_json_request(
            self._get_catalog_module_url(catalog_module_id), method="DELETE"
        )


class Projects:
    def __init__(self, session: Session):
        self.session = session

    def _get_projects_url(self, project_id: int | None = None) -> str:
        return "/projects" if project_id is None else "/projects/%d" % project_id

    def list_projects(self) -> list[dict]:
        return self.session._process_json_request(
            self._get_projects_url(), method="GET"
        )

    def create_project(self, project_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_projects_url(), project_data, method="POST"
        )

    def get_project(self, project_id) -> dict:
        return self.session._process_json_request(
            self._get_projects_url(project_id), method="GET"
        )

    def update_project(self, project_id, project_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_projects_url(project_id), project_data, method="PUT"
        )

    def delete_project(self, project_id):
        return self.session._process_json_request(
            self._get_projects_url(project_id), method="DELETE"
        )


class Requirements:
    def __init__(self, session: Session):
        self.session = session

    def _get_requirements_url(self, project_id: int) -> str:
        return "/projects/%d/requirements" % project_id

    def _get_requirement_url(self, requirement_id: int) -> str:
        return "/requirements/%d" % requirement_id

    def list_requirements(self, project_id: int) -> list[dict]:
        return self.session._process_json_request(
            self._get_requirements_url(project_id), method="GET"
        )

    def create_requirement(self, project_id: int, requirement_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_requirements_url(project_id), requirement_data, method="POST"
        )

    def get_requirement(self, requirement_id: int) -> dict:
        return self.session._process_json_request(
            self._get_requirement_url(requirement_id), method="GET"
        )

    def update_requirement(self, requirement_id: int, requirement_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_requirement_url(requirement_id), requirement_data, method="PUT"
        )

    def delete_requirement(self, requirement_id: int):
        return self.session._process_json_request(
            self._get_requirement_url(requirement_id), method="DELETE"
        )


class Measures:
    def __init__(self, session: Session):
        self.session = session

    def _get_measures_url(self, requirement_id: int) -> str:
        return "/requirements/%d/measures" % requirement_id

    def _get_measure_url(self, measure_id: int) -> str:
        return "/measures/%d" % measure_id

    def list_measures(self, requirement_id: int) -> list[dict]:
        return self.session._process_json_request(
            self._get_measures_url(requirement_id), method="GET"
        )

    def create_measure(self, requirement_id: int, measure_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_measures_url(requirement_id), measure_data, method="POST"
        )

    def get_measure(self, measure_id: int) -> dict:
        return self.session._process_json_request(
            self._get_measure_url(measure_id), method="GET"
        )

    def update_measure(self, measure_id: int, measure_data: dict) -> dict:
        return self.session._process_json_request(
            self._get_measure_url(measure_id), measure_data, method="PUT"
        )

    def delete_measure(self, measure_id: int):
        return self.session._process_json_request(
            self._get_measure_url(measure_id), method="DELETE"
        )
