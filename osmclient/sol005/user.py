#
# Copyright 2018 Telefonica Investigacion y Desarrollo S.A.U.
#
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
OSM user mgmt API
"""

from osmclient.common import utils
from osmclient.common.exceptions import ClientException
from osmclient.common.exceptions import NotFound
import json
import yaml


class User(object):
    def __init__(self, http=None, client=None):
        self._http = http
        self._client = client
        self._apiName = '/admin'
        self._apiVersion = '/v1'
        self._apiResource = '/users'
        self._apiBase = '{}{}{}'.format(self._apiName,
                                        self._apiVersion, self._apiResource)

    def create(self, name, user):
        """Creates a new OSM user
        """
        if 'projects' in user and user['projects'] is not None:
            user['projects'] = yaml.safe_load(user['projects'])
        http_code, resp = self._http.post_cmd(endpoint=self._apiBase,
                                       postfields_dict=user)
        #print('HTTP CODE: {}'.format(http_code))
        #print('RESP: {}'.format(resp))
        if http_code in (200, 201, 202, 204):
            if resp:
                resp = json.loads(resp)
            if not resp or 'id' not in resp:
                raise ClientException('unexpected response from server - {}'.format(
                                      resp))
            print(resp['id'])
        else:
            msg = ""
            if resp:
                try:
                    msg = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to create user {} - {}".format(name, msg))

    def update(self, name, user):
        """Updates an existing OSM user identified by name
        """
        myuser  = self.get(name)
        http_code, resp = self._http.put_cmd(endpoint='{}/{}'.format(self._apiBase,myuser['_id']),
                                       postfields_dict=user)
        #print('HTTP CODE: {}'.format(http_code))
        #print('RESP: {}'.format(resp))
        if http_code in (200, 201, 202, 204):
            if resp:
                resp = json.loads(resp)
            if not resp or 'id' not in resp:
                raise ClientException('unexpected response from server - {}'.format(
                                      resp))
            print(resp['id'])
        else:
            msg = ""
            if resp:
                try:
                    msg = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to update user {} - {}".format(name, msg))

    def delete(self, name, force=False):
        """Deletes an existing OSM user identified by name
        """
        user = self.get(name)
        querystring = ''
        if force:
            querystring = '?FORCE=True'
        http_code, resp = self._http.delete_cmd('{}/{}{}'.format(self._apiBase,
                                         user['_id'], querystring))
        #print('HTTP CODE: {}'.format(http_code))
        #print('RESP: {}'.format(resp))
        if http_code == 202:
            print('Deletion in progress')
        elif http_code == 204:
            print('Deleted')
        elif resp and 'result' in resp:
            print('Deleted')
        else:
            msg = ""
            if resp:
                try:
                    msg = json.loads(resp)
                except ValueError:
                    msg = resp
            raise ClientException("failed to delete user {} - {}".format(name, msg))

    def list(self, filter=None):
        """Returns the list of OSM users
        """
        filter_string = ''
        if filter:
            filter_string = '?{}'.format(filter)
        resp = self._http.get_cmd('{}{}'.format(self._apiBase,filter_string))
        #print('RESP: {}'.format(resp))
        if resp:
            return resp
        return list()

    def get(self, name):
        """Returns an OSM user based on name or id
        """
        if utils.validate_uuid4(name):
            for user in self.list():
                if name == user['_id']:
                    return user
        else:
            for user in self.list():
                if name == user['name']:
                    return user
        raise NotFound("User {} not found".format(name))


