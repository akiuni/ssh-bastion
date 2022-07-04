package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"gopkg.in/yaml.v2"
)

type SSHConfig struct {
	Global  SSHConfigGlobal            `yaml:"global"`
	Servers map[string]SSHConfigServer `yaml:"servers"`
	Groups  []string                   `yaml:"groups"`
	ACLs    map[string]SSHConfigACL    `yaml:"acls"`
	Users   map[string]SSHConfigUser   `yaml:"users"`
}

type SSHConfigGlobal struct {
	GroupPath            string   `yaml:"group_path"`
	MOTDPath             string   `yaml:"motd_path"`
	LogPath              string   `yaml:"log_path"`
	StoragePath          string   `yaml:"storage_path"`
	BastionPrivateKeys   []string `yaml:"bastion_private_keys"`
	AuthWithBastionKeys  bool     `yaml:"auth_with_bastion_keys"`
	IgnoreHostPubKeys    bool     `yaml:"ignore_hosts_pubkeys"`
	AllowAgentForwarding bool     `yaml:"allow_agent_forwarding"`
	AuthType             string   `yaml:"auth_type"`
	LDAP_Server          string   `yaml:"ldap_server"`
	LDAP_Domain          string   `yaml:"ldap_domain"`
	PassPassword         bool     `yaml:"pass_password"`
	ListenPath           string   `yaml:"listen_path"`
	NoIP6Bind            bool     `yaml:"disable_ipv6_bind"`
	ConnectTimeout       string   `yaml:"connect_timeout"`
	FluentbitServer      string   `yaml:"fluentbit_server"`
}

type SSHConfigACL struct {
	AllowedServers []string `yaml:"allow_servers"`
	AllowedGroups  []string `yaml:"allow_groups"`
}

type SSHConfigUser struct {
	ACL                string `yaml:"acl"`
	AuthorizedKeyStr   string `yaml:"authorized_key"`
	AuthorizedKeysFile string `yaml:"authorized_keys_file"`
}

type SSHConfigServer struct {
	HostPubKeys []string `yaml:"host_pubkeys"`
	ConnectPath string   `yaml:"connect_path"`
	LoginUser   string   `yaml:"login_user"`
	Group       string   ""
}

func fetchConfig(filename string) (*SSHConfig, error) {
	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to open config file: %s", err)
	}

	config := &SSHConfig{}

	err = yaml.Unmarshal(configData, config)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse YAML config file: %s", err)
	}

	for i, v := range config.Global.BastionPrivateKeys {
		config.Global.BastionPrivateKeys[i], err = loadKey(v)
		if err != nil {
			return nil, fmt.Errorf("Unable to load key %s: %v", v, err)
		}
	}

	for _, group := range config.Groups {
		groupData, err := ioutil.ReadFile(config.Global.GroupPath + "/" + group + ".yaml")
		if err != nil {
			return nil, fmt.Errorf("Failed to open group file: %s", err)
		}
		var t map[string]SSHConfigServer
		err = yaml.Unmarshal(groupData, &t)
		if err != nil {
			return nil, fmt.Errorf("Unable to parse YAML group file: %s", err)
		}
		for k_target, target := range t {
			target.Group = group
			config.Servers[k_target] = target

			for k_acl, acl := range config.ACLs {
				acl_dup := acl
				for _, a := range acl.AllowedGroups {
					if a == group {
						acl_dup.AllowedServers = append(acl.AllowedServers, k_target)
						break
					}
				}
				config.ACLs[k_acl] = acl_dup
			}

			for i, v := range target.HostPubKeys {
				config.Servers[k_target].HostPubKeys[i], err = loadKey(v)
				if err != nil {
					return nil, fmt.Errorf("Unable to load key %s: %v", v, err)
				}
			}

		}

	}

	resp, err := http.Get(config.Global.FluentbitServer)
	if err != nil {
		return nil, fmt.Errorf("Unable to join %s: %v", config.Global.FluentbitServer, err)
	}
	defer resp.Body.Close()
	return config, nil
}

func loadKey(target string) (string, error) {
	s := strings.Split(target, "file:")
	if len(s) == 1 {
		return s[0], nil
	} else if len(s) == 2 {
		key, err := ioutil.ReadFile(s[1])
		if err != nil {
			return "", fmt.Errorf("Unable to load key file %s: %v", s[1], err)
		}
		return string(key), nil
	}
	return "", fmt.Errorf("Bad key description %s", target)
}
