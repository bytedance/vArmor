package seccomp

import (
	"encoding/base64"
	"os"
)

func SaveSeccompProfile(fileName string, content string) error {
	c, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		return err
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(c)
	return err
}

func SeccompProfileExist(profilePath string) bool {
	_, err := os.Stat(profilePath)
	return !os.IsNotExist(err)
}

func RemoveSeccompProfile(profilePath string) error {
	return os.Remove(profilePath)
}
