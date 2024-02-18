#!/bin/bash
sudo apt -y install build-essential libelf-dev pkg-config
wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
chmod +x /tmp/llvm.sh
/tmp/llvm.sh 17
sudo apt -y install libapparmor-dev