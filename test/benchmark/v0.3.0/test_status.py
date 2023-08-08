#!/usr/bin/python3

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

import requests
import threading
import json

def send_status(num):
    status = dict()
    i = 0
    while i < 100:
        status["namespace"]="test"
        status["armorProfile"]="varmor-test-test"
        status["nodeName"]="thread-" + str(num)  + "-" + str(i)
        status["status"]="succeeded"
        status["message"]="Ready"
        i += 1
        requests.post("http://[address]:8080/api/v1/status", data=json.dumps(status), headers={"Content-Type":"application/json"})

    print("[+] thread-" + str(num) + " done.")

threads = []
for i in range(1, 5):
    t = threading.Thread(target=send_status, args=(i,))
    t.start()
    threads.append(t)

for thread in threads:
    thread.join()

print("[+] Done")
