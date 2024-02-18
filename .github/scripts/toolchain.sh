#!/bin/bash
sudo apt -y install build-essential libelf-dev pkg-config
wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
chmod +x /tmp/llvm.sh
sudo /tmp/llvm.sh 17
sudo ln -s $(which llvm-strip-17) /usr/local/bin/llvm-strip
sudo apt -y install libapparmor-dev
sudo apt install libseccomp-dev