package core

import (
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

const ConfigFileName = "ember.toml"

func LoadHosts() (HostMap, error) {

	if _, err := os.Stat(ConfigFileName); os.IsNotExist(err) {
		return make(HostMap), nil
	}

	data, err := os.ReadFile(ConfigFileName)
	if err != nil {
		return nil, err
	}

	var hosts HostMap
	if err := toml.Unmarshal(data, &hosts); err != nil {
		return nil, err
	}

	if hosts == nil {
		hosts = make(HostMap)
	}

	return hosts, nil
}

func SaveHosts(hosts HostMap) error {
	data, err := toml.Marshal(hosts)
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigFileName, data, 0644)
}

func GetConfigPath() string {
	path, err := filepath.Abs(ConfigFileName)
	if err != nil {
		return ConfigFileName
	}
	return path
}
