<!--
Copyright 2020 ETSI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied.
See the License for the specific language governing permissions and
limitations under the License
-->
# python-osmclient

OSM client library and console script

## Installation

### From git-repo

```bash
# Ubuntu 18.04 pre-requirements
sudo apt-get install python3-pip libcurl4-openssl-dev libssl-dev
# CentOS pre-requirements
# sudo yum install python3-pip libcurl-devel gnutls-devel
sudo -H python3 -m pip install python-magic
# Install OSM Information model
sudo -H python3 -m pip install git+https://osm.etsi.org/gerrit/osm/IM --upgrade
# Install OSM client from the git repo.
# You can install the latest client from master branch in this way:
sudo -H python3 -m pip install git+https://osm.etsi.org/gerrit/osm/osmclient
# You could also install a specific tag/version in this way
# sudo -H python3 -m pip install git+https://osm.etsi.org/gerrit/osm/osmclient@v7.0.0rc1
```

### From cloned repo (for developers)

```
# Ubuntu 18.04 pre-requirements
sudo apt-get install python3-pip libcurl4-openssl-dev libssl-dev
# Centos pre-requirements
# sudo yum install python3-pip libcurl-devel gnutls-devel
sudo -H python3 -m pip install python-magic
# Install OSM Information model
sudo -H python3 -m pip install git+https://osm.etsi.org/gerrit/osm/IM --upgrade
# Clone the osmclient repo and install OSM client from the git repo.
git clone https://osm.etsi.org/gerrit/osm/osmclient
cd osmclient
python3 -m pip install --user -e .
# logout and login so that PATH can be updated. Executable osm will be found in /home/ubuntu/.local/bin
```

## Setup

Set the OSM_HOSTNAME variable to the host of the OSM server (default: localhost).

```bash
localhost$ export OSM_HOSTNAME=<hostname>
```

## Examples

### upload vnfd

```bash
localhost$ osm upload-package ubuntu_xenial_vnf.tar.gz
{'transaction_id': 'ec12af77-1b91-4c84-b233-60f2c2c16d14'}
localhost$ osm vnfd-list
+--------------------+--------------------+
| vnfd name          | id                 |
+--------------------+--------------------+
| ubuntu_xenial_vnfd | ubuntu_xenial_vnfd |
+--------------------+--------------------+
```

### upload nsd

```bash
localhost$ osm upload-package ubuntu_xenial_ns.tar.gz
{'transaction_id': 'b560c9cb-43e1-49ef-a2da-af7aab24ce9d'}
localhost$ osm nsd-list
+-------------------+-------------------+
| nsd name          | id                |
+-------------------+-------------------+
| ubuntu_xenial_nsd | ubuntu_xenial_nsd |
+-------------------+-------------------+
```

### vim-list

```bash
localhost$ osm vim-list
+-------------+-----------------+--------------------------------------+
| ro-account  | datacenter name | uuid                                 |
+-------------+-----------------+--------------------------------------+
| osmopenmano | openstack-site  | 2ea04690-0e4a-11e7-89bc-00163e59ff0c |
+-------------+-----------------+--------------------------------------+
```

### instantiate ns

```bash
localhost$ osm ns-create ubuntu_xenial_nsd testns openstack-site
{'success': ''}
localhost$ osm ns-list
+------------------+--------------------------------------+-------------------+--------------------+---------------+
| ns instance name | id                                   | catalog name      | operational status | config status |
+------------------+--------------------------------------+-------------------+--------------------+---------------+
| testns           | 6b0d2906-13d4-11e7-aa01-b8ac6f7d0c77 | ubuntu_xenial_nsd | running            | configured    |
+------------------+--------------------------------------+-------------------+--------------------+---------------+
```

## Using osmclient as a library to interact with OSM

Assuming that you have installed python-osmclient package, it's pretty simple to write some Python code to interact with OSM.

### Simple Python code to get the list of NS packages

```python
from osmclient import client
from osmclient.common.exceptions import ClientException
hostname = "127.0.0.1"
myclient = client.Client(host=hostname, sol005=True)
resp = myclient.nsd.list()
print yaml.safe_dump(resp, indent=4, default_flow_style=False)
```

### Simple Python code to get the list of VNF packages from a specific user and project

The code will print for each package a pretty table, then the full details in yaml

```python
from osmclient import client
from osmclient.common.exceptions import ClientException
import yaml
from prettytable import PrettyTable
hostname = "127.0.0.1"
user = admin
password = admin
project = admin
kwargs = {}
if user is not None:
    kwargs['user']=user
if password is not None:
    kwargs['password']=password
if project is not None:
   kwargs['project']=project
myclient = client.Client(host=hostname, sol005=True, **kwargs)
resp = myclient.vnfd.list()
print yaml.safe_dump(resp, indent=4, default_flow_style=False)
```

## Enable autocompletion

You can enable autocompletion in OSM client by creating a file osm-complete.sh in the following way:

```bash
mkdir -p $HOME/.bash_completion.d
_OSM_COMPLETE=source osm > $HOME/.bash_completion.d/osm-complete.sh
```

Then you can add the following to your $HOME/.bashrc file:

```bash
. .bash_completion.d/osm-complete.sh
```

