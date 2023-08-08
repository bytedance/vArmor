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
from .api import api as api_blueprint
from .probes import probes as probes_blueprint

def create_app():
    app = flask.Flask(__name__)
    app.register_blueprint(api_blueprint, url_prefix='/api/v1')
    app.register_blueprint(probes_blueprint, url_prefix='/')
    return app
