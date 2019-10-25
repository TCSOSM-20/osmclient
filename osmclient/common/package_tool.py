# /bin/env python3
# Copyright 2019 ATOS
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

from osmclient.common.exceptions import ClientException
import os
import glob
import time
import tarfile
import hashlib
from osm_im.validation import Validation as validation_im
from jinja2 import Environment, PackageLoader


class PackageTool(object):
    def __init__(self, client=None):
        self._client = client

    def create(self, package_type, base_directory, package_name, override, image, vdus, vcpu, memory, storage,
               interfaces, vendor, detailed, netslice_subnets, netslice_vlds):
        """
            **Create a package descriptor**

            :params:
                - package_type: [vnf, ns, nst]
                - base directory: path of destination folder
                - package_name: is the name of the package to be created
                - image: specify the image of the vdu
                - vcpu: number of virtual cpus of the vdu
                - memory: amount of memory in MB pf the vdu
                - storage: amount of storage in GB of the vdu
                - interfaces: number of interfaces besides management interface
                - vendor: vendor name of the vnf/ns
                - detailed: include all possible values for NSD, VNFD, NST
                - netslice_subnets: number of netslice_subnets for the NST
                - netslice_vlds: number of virtual link descriptors for the NST

            :return: status
        """

        # print("location: {}".format(osmclient.__path__))
        file_loader = PackageLoader("osmclient")
        env = Environment(loader=file_loader)
        if package_type == 'ns':
            template = env.get_template('nsd.yaml.j2')
            content = {"name": package_name, "vendor": vendor, "vdus": vdus, "clean": False, "interfaces": interfaces,
                       "detailed": detailed}
        elif package_type == 'vnf':
            template = env.get_template('vnfd.yaml.j2')
            content = {"name": package_name, "vendor": vendor, "vdus": vdus, "clean": False, "interfaces": interfaces,
                       "image": image, "vcpu": vcpu, "memory": memory, "storage": storage, "detailed": detailed}
        elif package_type == 'nst':
            template = env.get_template('nst.yaml.j2')
            content = {"name": package_name, "vendor": vendor, "interfaces": interfaces,
                       "netslice_subnets": netslice_subnets, "netslice_vlds": netslice_vlds, "detailed": detailed}
        else:
            raise ClientException("Wrong descriptor type {}. Options: ns, vnf, nst".format(package_type))

        # print("To be rendered: {}".format(content))
        output = template.render(content)
        # print(output)

        structure = self.discover_folder_structure(base_directory, package_name, override)
        if structure.get("folders"):
            self.create_folders(structure["folders"], package_type)
        if structure.get("files"):
            self.create_files(structure["files"], output, package_type)
        return "Created"

    def validate(self, base_directory):
        """
            **Validate OSM Descriptors given a path**

            :params:
                - base_directory is the root path for all descriptors

            :return: List of dict of validated descriptors. keys: type, path, valid, error
        """
        table = []
        descriptors_paths = [f for f in glob.glob(base_directory + "/**/*.yaml", recursive=True)]
        print("Base directory: {}".format(base_directory))
        print("{} Descriptors found to validate".format(len(descriptors_paths)))
        for desc_path in descriptors_paths:
            with open(desc_path) as descriptor_file:
                descriptor_data = descriptor_file.read()
            desc_type = "-"
            try:
                desc_type, descriptor_data = validation_im.yaml_validation(self, descriptor_data)
                validation_im.pyangbind_validation(self, desc_type, descriptor_data)
                table.append({"type": desc_type, "path": desc_path, "valid": "OK", "error": "-"})
            except Exception as e:
                table.append({"type": desc_type, "path": desc_path, "valid": "ERROR", "error": str(e)})
        return table

    def build(self, package_folder, skip_validation=True):
        """
            **Creates a .tar.gz file given a package_folder**

            :params:
                - package_folder: is the name of the folder to be packaged
                - skip_validation: is the flag to validate or not the descriptors on the folder before build

            :returns: message result for the build process
        """

        if not os.path.exists("{}".format(package_folder)):
            return "Fail, package is not in the specified route"
        if not skip_validation:
            results = self.validate(package_folder)
            for result in results:
                if result["valid"] != "OK":
                    return("There was an error validating the file: {} with error: {}".format(result["path"],
                                                                                              result["error"]))
        self.calculate_checksum(package_folder)
        with tarfile.open("{}.tar.gz".format(package_folder), mode='w:gz') as archive:
            print("Adding File: {}".format(package_folder))
            archive.add('{}'.format(package_folder), recursive=True)
        return "Created {}.tar.gz".format(package_folder)

    def calculate_checksum(self, package_folder):
        """
            **Function to calculate the checksum given a folder**

            :params:
                - package_folder: is the folder where we have the files to calculate the checksum
            :returns: None
        """
        files = [f for f in glob.glob(package_folder + "/**/*.*", recursive=True)]
        checksum = open("{}/checksum.txt".format(package_folder), "w+")
        for file_item in files:
            if "checksum.txt" in file_item:
                continue
            # from https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
            md5_hash = hashlib.md5()
            with open(file_item, "rb") as f:
                # Read and update hash in chunks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    md5_hash.update(byte_block)
                checksum.write("{}\t{}\n".format(md5_hash.hexdigest(), file_item))
        checksum.close()

    def create_folders(self, folders, package_type):
        """
            **Create folder given a list of folders**

            :params:
                - folders: [List] list of folders paths to be created
                - package_type: is the type of package to be created
            :return: None
        """

        for folder in folders:
            try:
                # print("Folder {} == package_type {}".format(folder[1], package_type))
                if folder[1] == package_type:
                    print("Creating folder:\t{}".format(folder[0]))
                    os.makedirs(folder[0])
            except FileExistsError:
                pass

    def save_file(self, file_name, file_body):
        """
            **Create a file given a name and the content**

            :params:
                - file_name: is the name of the file with the relative route
                - file_body: is the content of the file
            :return: None
        """
        print("Creating file:  \t{}".format(file_name))
        try:
            with open(file_name, "w+") as f:
                f.write(file_body)
        except Exception as e:
            raise ClientException(e)

    def generate_readme(self):
        """
            **Creates the README content**

            :returns: readme content
        """
        return """# Descriptor created by OSM descriptor package generated\n\n**Created on {} **""".format(
               time.strftime("%m/%d/%Y, %H:%M:%S", time.localtime()))

    def generate_cloud_init(self):
        """
            **Creates the cloud-init content**

            :returns: cloud-init content
        """
        return "---\n#cloud-config"

    def create_files(self, files, file_content, package_type):
        """
            **Creates the files given the file list and type**

            :params:
                - files: is the list of files structure
                - file_content: is the content of the descriptor rendered by the template
                - package_type: is the type of package to filter the creation structure

            :return: None
        """
        for file_item, file_package, file_type in files:
            if package_type == file_package:
                if file_type == "descriptor":
                    self.save_file(file_item, file_content)
                elif file_type == "readme":
                    self.save_file(file_item, self.generate_readme())
                elif file_type == "cloud_init":
                    self.save_file(file_item, self.generate_cloud_init())

    def check_files_folders(self, path_list, override):
        """
            **Find files and folders missing given a directory structure {"folders": [], "files": []}**

            :params:
                - path_list: is the list of files and folders to be created
                - override: is the flag used to indicate the creation of the list even if the file exist to override it

            :return: Missing paths Dict
        """
        missing_paths = {}
        folders = []
        files = []
        for folder in path_list.get("folders"):
            if not os.path.exists(folder[0]):
                folders.append(folder)
        missing_paths["folders"] = folders

        for file_item in path_list.get("files"):
            if not os.path.exists(file_item[0]) or override is True:
                files.append(file_item)
        missing_paths["files"] = files

        return missing_paths

    def discover_folder_structure(self, base_directory, name, override):
        """
            **Discover files and folders structure for OSM descriptors given a base_directory and name**

            :params:
                - base_directory: is the location of the package to be created
                - name: is the name of the package
                - override: is the flag used to indicate the creation of the list even if the file exist to override it
            :return: Files and Folders not found. In case of override, it will return all file list
        """
        prefix = "{}/{}".format(base_directory, name)
        files_folders = {"folders": [("{}_ns".format(prefix), "ns"),
                                     ("{}_ns/icons".format(prefix), "ns"),
                                     ("{}_ns/charms".format(prefix), "ns"),
                                     ("{}_vnf".format(name), "vnf"),
                                     ("{}_vnf/charms".format(prefix), "vnf"),
                                     ("{}_vnf/cloud_init".format(prefix), "vnf"),
                                     ("{}_vnf/images".format(prefix), "vnf"),
                                     ("{}_vnf/icons".format(prefix), "vnf"),
                                     ("{}_vnf/scripts".format(prefix), "vnf"),
                                     ("{}_nst".format(prefix), "nst"),
                                     ("{}_nst/icons".format(prefix), "nst")
                                     ],
                         "files": [("{}_ns/{}_nsd.yaml".format(prefix, name), "ns", "descriptor"),
                                   ("{}_ns/README.md".format(prefix), "ns", "readme"),
                                   ("{}_vnf/{}_vnfd.yaml".format(prefix, name), "vnf", "descriptor"),
                                   ("{}_vnf/cloud_init/cloud-config.txt".format(prefix), "vnf", "cloud_init"),
                                   ("{}_vnf/README.md".format(prefix), "vnf", "readme"),
                                   ("{}_nst/{}_nst.yaml".format(prefix, name), "nst", "descriptor"),
                                   ("{}_nst/README.md".format(prefix), "nst", "readme")
                                   ]
                         }
        missing_files_folders = self.check_files_folders(files_folders, override)
        # print("Missing files and folders: {}".format(missing_files_folders))
        return missing_files_folders
