#!/bin/bash
# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

set -e
set -x

#Figlet is required for ctverif printing
sudo apt-get install -y figlet

#Install boogieman
#sudo gem install --pre bam-bam-boogieman
git clone https://github.com/Qthan/bam-bam-boogieman.git -b cost-modeling
cd bam-bam-boogieman
bundle update
bundle exec rake install
cd ..
which bam
exit 1



#Install the apt-get dependencies from the smack build script: this way they will still be there
#when we get things from cache
DEPENDENCIES="git cmake python-yaml python-psutil unzip wget python3-yaml"
DEPENDENCIES+=" mono-complete libz-dev libedit-dev"

# Adding MONO repository
sudo add-apt-repository "deb http://download.mono-project.com/repo/debian wheezy main"
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF

sudo apt-get update
sudo apt-get install -y ${DEPENDENCIES}
pip install pyyaml


clang --version
clang-3.9 --version

which python
python --version
pip install psutil
