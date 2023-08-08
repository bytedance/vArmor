# The DefenseInDepth mode [Experimental]
* BTF (BPF Type Format) must be enabled.
* Or the kernel version of [veLinux OS](https://www.volcengine.com/docs/6396/74967) is 5.4.143 or above.  
* The Nodes must have the rsyslog installed and enabled, and must not have the auditd enabled. 
* Run the following shell script when adding new nodes:
```
#!/bin/bash

cat >/etc/rsyslog.d/varmor.conf<<EOF
\$ModLoad omuxsock
\$OMUxSockSocket /var/run/varmor/audit/omuxsock.sock

kern.* :omuxsock:;
EOF

systemctl restart rsyslog.service
```
* Install and enable the DefenseInDepth mode
```
helm install varmor varmor-0.3.3.tgz \
    -n varmor \
    --set "defenseInDepth.enabled=true" \
    --set image.registry="elkeid-test-cn-beijing.cr.volces.com" \
    --set image.username="[USERNAME]" \
    --set image.password="[PASSWORD]"
```
