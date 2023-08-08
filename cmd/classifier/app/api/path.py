# coding: utf-8

# Copyright 2022 vArmor Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import flask
import json
import os
from . import api
from stringlifier.api import Stringlifier

lifier = Stringlifier()
lifier_types = [
    '<RANDOM_STRING>',
    '<NUMERIC>',
    '<IP_ADDR>',
    '<UUID>',
    '<JWT>',
]

@api.route('/path', methods=['POST'])
def handle_path_trim():
    try:
        path = flask.request.get_data().decode('utf-8')
        new_path = lifier(path)[0]
        old_path_names = path.split('/')
        new_path_names = new_path.split('/')
        new_path = '/'

        for i, new_path_name in enumerate(new_path_names):
            find = False
            for lifier_type in lifier_types:
                if lifier_type in new_path_name:
                    find = True
                    break
            if find:
                new_path = os.path.join(new_path, '*')
            else:
                new_path = os.path.join(new_path, old_path_names[i])

        if '*' in new_path:
            path = new_path

        return flask.make_response(path, 200)
    except Exception as e:
        return flask.make_response("", 500)
