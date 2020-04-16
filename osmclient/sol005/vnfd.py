# Copyright 2018 Telefonica
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
OSM vnfd API handling
"""

from osmclient.common.exceptions import NotFound
from osmclient.common.exceptions import ClientException
from osmclient.common import utils
import json
import yaml
import magic
from os.path import basename
import logging
import os.path
from urllib.parse import quote
import tarfile
from osm_im.validation import Validation as validation_im


class Vnfd(object):

    def __init__(self, http=None, client=None):
        self._http = http
        self._client = client
        self._logger = logging.getLogger('osmclient')
        self._apiName = '/vnfpkgm'
        self._apiVersion = '/v1'
        self._apiResource = '/vnf_packages'
        self._apiBase = '{}{}{}'.format(self._apiName,
                                        self._apiVersion, self._apiResource)
        #self._apiBase='/vnfds'

    def list(self, filter=None):
        self._logger.debug("")
        self._client.get_token()
        filter_string = ''
        if filter:
            filter_string = '?{}'.format(filter)
        _, resp = self._http.get2_cmd('{}{}'.format(self._apiBase,filter_string))
        if resp:
            return json.loads(resp)
        return list()

    def get(self, name):
        self._logger.debug("")
        self._client.get_token()
        if utils.validate_uuid4(name):
            for vnfd in self.list():
                if name == vnfd['_id']:
                    return vnfd
        else:
            for vnfd in self.list():
                if 'name' in vnfd and name == vnfd['name']:
                    return vnfd
        raise NotFound("vnfd {} not found".format(name))

    def get_individual(self, name):
        self._logger.debug("")
        vnfd = self.get(name)
        # It is redundant, since the previous one already gets the whole vnfpkginfo
        # The only difference is that a different primitive is exercised
        try:
            _, resp = self._http.get2_cmd('{}/{}'.format(self._apiBase, vnfd['_id']))
            #print(yaml.safe_dump(resp))
            if resp:
                return json.loads(resp)
        except NotFound:
            raise NotFound("vnfd '{}' not found".format(name))
        raise NotFound("vnfd '{}' not found".format(name))

    def get_thing(self, name, thing, filename):
        self._logger.debug("")
        vnfd = self.get(name)
        headers = self._client._headers
        headers['Accept'] = 'application/binary'
        http_code, resp = self._http.get2_cmd('{}/{}/{}'.format(self._apiBase, vnfd['_id'], thing))
        #print('HTTP CODE: {}'.format(http_code))
        #print('RESP: {}'.format(resp))
        #if http_code in (200, 201, 202, 204):
        if resp:
            #store in a file
            return json.loads(resp)
        #else:
        #    msg = ""
        #    if resp:
        #        try:
        #            msg = json.loads(resp)
        #        except ValueError:
        #            msg = resp
        #    raise ClientException("failed to get {} from {} - {}".format(thing, name, msg))

    def get_descriptor(self, name, filename):
        self._logger.debug("")
        self.get_thing(name, 'vnfd', filename)

    def get_package(self, name, filename):
        self._logger.debug("")
        self.get_thing(name, 'package_content', filename)

    def get_artifact(self, name, artifact, filename):
        self._logger.debug("")
        self.get_thing(name, 'artifacts/{}'.format(artifact), filename)

    def delete(self, name, force=False):
        self._logger.debug("")
        self._client.get_token()
        vnfd = self.get(name)
        querystring = ''
        if force:
            querystring = '?FORCE=True'
        http_code, resp = self._http.delete_cmd('{}/{}{}'.format(self._apiBase,
                                         vnfd['_id'], querystring))
        #print('HTTP CODE: {}'.format(http_code))
        #print('RESP: {}'.format(resp))
        if http_code == 202:
            print('Deletion in progress')
        elif http_code == 204:
            print('Deleted')
        else:
            msg = resp or ""
            # if resp:
            #     try:
            #         msg = json.loads(resp)
            #     except ValueError:
            #         msg = resp
            raise ClientException("failed to delete vnfd {} - {}".format(name, msg))

    def create(self, filename, overwrite=None, update_endpoint=None, skip_charm_build=False,
               override_epa=False, override_nonepa=False, override_paravirt=False):
        self._logger.debug("")
        if os.path.isdir(filename):
            filename = filename.rstrip('/')
            filename = self._client.package_tool.build(filename, skip_validation=False, skip_charm_build=skip_charm_build)
            print('Uploading package {}'.format(filename))
            self.create(filename, overwrite=overwrite, update_endpoint=update_endpoint,
                        override_epa=override_epa, override_nonepa=override_nonepa,
                        override_paravirt=override_paravirt)
        else:
            self._client.get_token()
            mime_type = magic.from_file(filename, mime=True)
            if mime_type is None:
                raise ClientException(
                    "Unexpected MIME type for file {}: MIME type {}".format(
                        filename, mime_type)
                )
            headers = self._client._headers
            headers['Content-Filename'] = basename(filename)
            if mime_type in ['application/yaml', 'text/plain', 'application/json']:
                headers['Content-Type'] = 'text/plain'
            elif mime_type in ['application/gzip', 'application/x-gzip']:
                headers['Content-Type'] = 'application/gzip'
                #headers['Content-Type'] = 'application/binary'
                # Next three lines are to be removed in next version
                #headers['Content-Filename'] = basename(filename)
                #file_size = stat(filename).st_size
                #headers['Content-Range'] = 'bytes 0-{}/{}'.format(file_size - 1, file_size)
            else:
                raise ClientException(
                         "Unexpected MIME type for file {}: MIME type {}".format(
                             filename, mime_type)
                      )
            special_ow_string = ''
            if override_epa or override_nonepa or override_paravirt:
                # If override for EPA, non-EPA or paravirt is required, get the descriptor data 
                descriptor_data = None
                if mime_type in ['application/yaml', 'text/plain', 'application/json']:
                    with open(filename) as df:
                        descriptor_data = df.read()
                elif mime_type in ['application/gzip', 'application/x-gzip']:
                    tar_object = tarfile.open(filename, "r:gz")
                    descriptor_list = []
                    for member in tar_object:
                        if member.isreg():
                            if '/' not in os.path.dirname(member.name) and member.name.endswith('.yaml'):
                                descriptor_list.append(member.name)
                    if len(descriptor_list) > 1:
                        raise ClientException('Found more than one potential descriptor in the tar.gz file')
                    elif len(descriptor_list) == 0:
                        raise ClientException('No descriptor was found in the tar.gz file')
                    with tar_object.extractfile(descriptor_list[0]) as df:
                        descriptor_data = df.read()
                    tar_object.close()
                if not descriptor_data:
                    raise ClientException('Descriptor could not be read')
                desc_type, vnfd = validation_im.yaml_validation(self, descriptor_data)
                validation_im.pyangbind_validation(self, desc_type, vnfd)
                vnfd = yaml.safe_load(descriptor_data)
                vdu_list = []
                for k in vnfd:
                    # Get only the first descriptor in case there are many in the yaml file
                    # k can be vnfd:vnfd-catalog or vnfd-catalog. This check is skipped
                    vdu_list = vnfd[k]['vnfd'][0]['vdu']
                    break;
                for vdu_number, vdu in enumerate(vdu_list):
                    if override_epa:
                        guest_epa = {}
                        guest_epa["mempage-size"] = "LARGE"
                        guest_epa["cpu-pinning-policy"] = "DEDICATED"
                        guest_epa["cpu-thread-pinning-policy"] = "PREFER"
                        guest_epa["numa-node-policy"] = {}
                        guest_epa["numa-node-policy"]["node-cnt"] = 1
                        guest_epa["numa-node-policy"]["mem-policy"] = "STRICT"
                        #guest_epa["numa-node-policy"]["node"] = []
                        #guest_epa["numa-node-policy"]["node"].append({"id": "0", "paired-threads": {"num-paired-threads": 1} })
                        special_ow_string = "{}vdu.{}.guest-epa={};".format(special_ow_string,vdu_number,quote(yaml.safe_dump(guest_epa)))
                        headers['Query-String-Format'] = 'yaml'
                    if override_nonepa:
                        special_ow_string = "{}vdu.{}.guest-epa=;".format(special_ow_string,vdu_number)
                    if override_paravirt:
                        for iface_number in range(len(vdu['interface'])):
                            special_ow_string = "{}vdu.{}.interface.{}.virtual-interface.type=PARAVIRT;".format(
                                                special_ow_string,vdu_number,iface_number)
                special_ow_string = special_ow_string.rstrip(";")

            headers["Content-File-MD5"] = utils.md5(filename)
            http_header = ['{}: {}'.format(key,val)
                             for (key,val) in list(headers.items())]
            self._http.set_http_header(http_header)
            if update_endpoint:
                http_code, resp = self._http.put_cmd(endpoint=update_endpoint, filename=filename)
            else:
                ow_string = ''
                if special_ow_string:
                    if overwrite:
                        overwrite = "{};{}".format(overwrite,special_ow_string)
                    else:
                        overwrite = special_ow_string
                if overwrite:
                    ow_string = '?{}'.format(overwrite)
                self._apiResource = '/vnf_packages_content'
                self._apiBase = '{}{}{}'.format(self._apiName,
                                                self._apiVersion, self._apiResource)
                endpoint = '{}{}'.format(self._apiBase,ow_string)
                http_code, resp = self._http.post_cmd(endpoint=endpoint, filename=filename)
            #print('HTTP CODE: {}'.format(http_code))
            #print('RESP: {}'.format(resp))
            if http_code in (200, 201, 202):
                if resp:
                    resp = json.loads(resp)
                if not resp or 'id' not in resp:
                     raise ClientException('unexpected response from server: '.format(resp))
                print(resp['id'])
            elif http_code == 204:
                print('Updated')
            # else:
            #     msg = "Error {}".format(http_code)
            #     if resp:
            #         try:
            #             msg = "{} - {}".format(msg, json.loads(resp))
            #         except ValueError:
            #             msg = "{} - {}".format(msg, resp)
            #     raise ClientException("failed to create/update vnfd - {}".format(msg))

    def update(self, name, filename):
        self._logger.debug("")
        self._client.get_token()
        vnfd = self.get(name)
        endpoint = '{}/{}/package_content'.format(self._apiBase, vnfd['_id'])
        self.create(filename=filename, update_endpoint=endpoint)

