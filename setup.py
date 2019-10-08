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
#
from setuptools import setup, find_packages

setup(
    name='osmclient',
    version_command=('git describe --match v* --tags --long --dirty',
                     'pep440-git-full'),
    author='Mike Marchetti',
    author_email='mmarchetti@sandvine.com',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Click', 'prettytable', 'pyyaml', 'pycurl', 'python-magic'
    ],
    setup_requires=['setuptools-version-command'],
    test_suite='nose.collector',
    entry_points={
        'console_scripts': [
            'osm = osmclient.scripts.osm:cli',
        ],
    },
)
