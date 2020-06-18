##
# Copyright 2020 ETSI
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
##

# Snap for OSM client

The snapcraft.yaml located in this folder, allows to build a snap of the OSM client


## Build

```bash
# Build the snap
$ snapcraft --use-lxd
...
Staging client
Priming client
Determining the version from the project repo (version: git).
The version has been set to 'v7.1.0+git4.a4af86f-dirty'
Snapping 'osmclient' \
Snapped 'osmclient_v7.1.0+git4.a4af86f-dirty_amd64.snap'
```

## Install

```bash
$ sudo snap install --devmode osmclient_v7.1.0+git4.a4af86f-dirty_amd64.snap
osmclient v7.1.0+git4.a4af86f-dirty installed
$ sudo snap alias osmclient.osm osm
```
