#!/bin/bash
wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
chmod +x /tmp/llvm.sh
./tmp/llvm.sh 17
apt install libapparmor-dev