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

from io import BytesIO
import pycurl
import json
import logging
import copy
from osmclient.common import http
from osmclient.common.exceptions import OsmHttpException, NotFound


class Http(http.Http):

    def __init__(self, url, user='admin', password='admin', **kwargs):
        self._url = url
        self._user = user
        self._password = password
        self._http_header = None
        self._logger = logging.getLogger('osmclient')
        self._default_query_admin = None
        self._all_projects = None;
        self._public = None;
        if 'all_projects' in kwargs:
            self._all_projects=kwargs['all_projects']
        if 'public' in kwargs:
            self._public=kwargs['public']
        self._default_query_admin = self._complete_default_query_admin()

    def _complete_default_query_admin(self):
        query_string_list=[]
        if self._all_projects:
            query_string_list.append("ADMIN")
        if self._public is not None:
            query_string_list.append("PUBLIC={}".format(self._public))
        return "&".join(query_string_list)

    def _complete_endpoint(self, endpoint):
        if self._default_query_admin:
            if '?' in endpoint:
                endpoint = '&'.join([endpoint, self._default_query_admin])
            else:
                endpoint = '?'.join([endpoint, self._default_query_admin])
        return endpoint

    def _get_curl_cmd(self, endpoint, skip_query_admin=False):
        self._logger.debug("")
        curl_cmd = pycurl.Curl()
        if self._logger.getEffectiveLevel() == logging.DEBUG:
            curl_cmd.setopt(pycurl.VERBOSE, True)
        if not skip_query_admin:
            endpoint = self._complete_endpoint(endpoint)
        curl_cmd.setopt(pycurl.URL, self._url + endpoint)
        curl_cmd.setopt(pycurl.SSL_VERIFYPEER, 0)
        curl_cmd.setopt(pycurl.SSL_VERIFYHOST, 0)
        if self._http_header:
            curl_cmd.setopt(pycurl.HTTPHEADER, self._http_header)
        return curl_cmd

    def delete_cmd(self, endpoint, skip_query_admin=False):
        self._logger.debug("")
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(endpoint, skip_query_admin)
        curl_cmd.setopt(pycurl.CUSTOMREQUEST, "DELETE")
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)
        self._logger.info("Request METHOD: {} URL: {}".format("DELETE",self._url + endpoint))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        self.check_http_response(http_code, data)
        # TODO 202 accepted should be returned somehow
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.verbose("Response DATA: {}".format(data_text))
            return http_code, data_text
        else:
            return http_code, None

    def send_cmd(self, endpoint='', postfields_dict=None,
                 formfile=None, filename=None,
                 put_method=False, patch_method=False,
                 skip_query_admin=False):
        self._logger.debug("")
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(endpoint, skip_query_admin)
        if put_method:
            curl_cmd.setopt(pycurl.CUSTOMREQUEST, "PUT")
        elif patch_method:
            curl_cmd.setopt(pycurl.CUSTOMREQUEST, "PATCH")
        curl_cmd.setopt(pycurl.POST, 1)
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)

        if postfields_dict is not None:
            jsondata = json.dumps(postfields_dict)
            if 'password' in postfields_dict:
                postfields_dict_copy = copy.deepcopy(postfields_dict)
                postfields_dict_copy['password']='******'
                jsondata_log = json.dumps(postfields_dict_copy)
            else:
                jsondata_log = jsondata
            self._logger.verbose("Request POSTFIELDS: {}".format(jsondata_log))
            curl_cmd.setopt(pycurl.POSTFIELDS, jsondata)
        elif formfile is not None:
            curl_cmd.setopt(
                pycurl.HTTPPOST,
                [((formfile[0],
                           (pycurl.FORM_FILE,
                            formfile[1])))])
        elif filename is not None:
            with open(filename, 'rb') as stream:
                postdata=stream.read()
            self._logger.verbose("Request POSTFIELDS: Binary content")
            curl_cmd.setopt(pycurl.POSTFIELDS, postdata)

        if put_method:
            self._logger.info("Request METHOD: {} URL: {}".format("PUT",self._url + endpoint))
        elif patch_method:
            self._logger.info("Request METHOD: {} URL: {}".format("PATCH",self._url + endpoint))
        else:
            self._logger.info("Request METHOD: {} URL: {}".format("POST",self._url + endpoint))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        self.check_http_response(http_code, data)
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.verbose("Response DATA: {}".format(data_text))
            return http_code, data_text
        else:
            return http_code, None

    def post_cmd(self, endpoint='', postfields_dict=None,
                 formfile=None, filename=None,
                 skip_query_admin=False):
        self._logger.debug("")
        return self.send_cmd(endpoint=endpoint,
                             postfields_dict=postfields_dict,
                             formfile=formfile, filename=filename,
                             put_method=False, patch_method=False,
                             skip_query_admin=skip_query_admin)

    def put_cmd(self, endpoint='', postfields_dict=None,
                formfile=None, filename=None,
                skip_query_admin=False):
        self._logger.debug("")
        return self.send_cmd(endpoint=endpoint,
                             postfields_dict=postfields_dict,
                             formfile=formfile, filename=filename,
                             put_method=True, patch_method=False,
                             skip_query_admin=skip_query_admin)

    def patch_cmd(self, endpoint='', postfields_dict=None,
                formfile=None, filename=None,
                skip_query_admin=False):
        self._logger.debug("")
        return self.send_cmd(endpoint=endpoint,
                             postfields_dict=postfields_dict,
                             formfile=formfile, filename=filename,
                             put_method=False, patch_method=True,
                             skip_query_admin=skip_query_admin)

    def get2_cmd(self, endpoint, skip_query_admin=False):
        self._logger.debug("")
        data = BytesIO()
        curl_cmd = self._get_curl_cmd(endpoint, skip_query_admin)
        curl_cmd.setopt(pycurl.HTTPGET, 1)
        curl_cmd.setopt(pycurl.WRITEFUNCTION, data.write)
        self._logger.info("Request METHOD: {} URL: {}".format("GET",self._url + endpoint))
        curl_cmd.perform()
        http_code = curl_cmd.getinfo(pycurl.HTTP_CODE)
        self._logger.info("Response HTTPCODE: {}".format(http_code))
        curl_cmd.close()
        self.check_http_response(http_code, data)
        if data.getvalue():
            data_text = data.getvalue().decode()
            self._logger.verbose("Response DATA: {}".format(data_text))
            return http_code, data_text
        return http_code, None

    def check_http_response(self, http_code, data):
        if http_code >= 300:
            resp = ""
            if data.getvalue():
                data_text = data.getvalue().decode()
                self._logger.verbose("Response {} DATA: {}".format(http_code, data_text))
                resp = ": " + data_text
            else:
                self._logger.verbose("Response {}".format(http_code))
            if http_code == 404:
                raise NotFound("Error {}{}".format(http_code, resp))
            raise OsmHttpException("Error {}{}".format(http_code, resp))

    def set_query_admin(self, **kwargs):
        if 'all_projects' in kwargs:
            self._all_projects=kwargs['all_projects']
        if 'public' in kwargs:
            self._public=kwargs['public']
        self._default_query_admin = self._complete_default_query_admin()
