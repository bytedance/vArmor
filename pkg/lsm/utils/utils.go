package utils

import (
	"bufio"
	"io"
	"os"
	"strings"
)

func RetrieveDiskDeviceList() ([]string, error) {
	f, err := os.Open("/proc/partitions")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReader(f)

	var devices []string
	for {
		p, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if strings.HasPrefix(p, "major") {
			continue
		} else {
			dev := strings.Fields(p)
			if len(dev) == 4 {
				devices = append(devices, dev[3])
			}
		}
	}
	return devices, nil
}
