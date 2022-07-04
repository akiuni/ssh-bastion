# SSH-BASTION
A logging SSH relay, with LDAP & public key auth.

## Goals

This application will MITM all SSH sessions directed at your internal servers and log the interactive sessions to disk.
Only interactive sessions are allowed, all other SSH channels (e.g. port forwarding, X11 forwarding) are denied, excepted ssh-agent for pass-through public key auth.

Each session will generate 3 log files,
 * a .txt file, containing the raw output of the session.
 * a .ttyrec file, which is a ttyrecord format recording, playable using "termplay".
 * a .sshreq file containing all of the SSH requests sent by the client to the remote server during the session.

> Note that If the bastion has been configured to send logs to an external server (e.g. syslog or fluentbit), then only the .sshreq file is created.


Authentication / session information is also logged to syslog with the LOG_AUTH | LOG_ALERT flags.

Only the output that is sent back to the client is logged, as the shell should echo any input from the client, with the exception of masked fields, like passwords.

The log directory is specified in the yaml config file and the files are stored in subdirectories of the year and month.

## How it works

When a user connects to the relay, they can authenticate with a user/pass which will be authed against LDAP (AD), or a public key allowed by the yaml config file.

After authenticating they will be presented a terminal waiting for user input. The user must send a part of the server name he wants to reach, the relay will return a list of corresponding servers he is allowed to connect to. After selecting the server, the user will be connect to it through the logging relay with the authentication method he used to connect to the relay.

## The yaml configuration file

The configuration file must be provided on startup with the `-c` switch. 
Here are the list of possible directives :

**Global section**

This section contains the daemon global configuration settings.

| Directive | Description | Example |
 --- | --- | --- 
| group_path | Path containing hosts groups | "config/groups" |
| motd_path | Display a message of the day to all users, path to plain text file with unix line endings. | "data/motd" |
| log_path | Path of directory with which to store session logs. | "data/logs" |
| storage_path | Path to uploaded and downloaded files | "data/storage" |
| bastion_private_keys | Array of private keys to identify the server, one per algorithm. <br />This array is also used as client keys on the target hosts if auth_with_bastion_keys is enabled. | "file:data/keys/ssh_host_rsa_key" |
| auth_with_bastion_keys | Use the server keys to identify on targets. | yes/no |
| ignore_hosts_pubkeys | Ignore or check target public keys (insecure) | yes/no |
| allow_agent_forwarding | Allow Agent forwarding to identify on targets | yes/no |
| auth_type | User/Pass auth type, currently either "ldap" (Active Directory) or "none" (disabled). | "ldap" |
| ldap_server | LDAP server path to perform AD auth against. | "dmu01.rsint.net:389" |
| ldap_domain |  LDAP domain to user when performing authentication, users in format <username>@ldap_domain | "rsint.net" |
| pass_password | Pass through LDAP password to host we are jumping to for auth? | yes/no |
| listen_path |Listen path for setting up the TCP listener. | "10.0.2.15:2222" |
| disable_ipv6_bind | Disable ipv6 bind in case of multisocket listen_path | yes/no |
| connect_timeout | Connection Timeout is optional, default is 30 seconds | "30s" |
| fluentbit_server | URL to the fluentbit server, this options disables txt and sshreq files | "http://fluentbit.srv.net" |


**Declaration of targets**

Targets are declared in the `servers` directive of the main configuration file and the `groups` directive which points to a separated configuration file.
Directives inside `servers` and the file pointed by `groups` are exactly the same.  In case of duplication, `servers` overrides `groups`.

For example, of the `groups` directive:
```
groups:
    - "cluster330"
    - "cluster331"
```
The files cluster330.yaml and  cluster331.yaml must exist inside the `group_path` global directive and contain declaration of targets.
Each target is referenced by its name, which then, must be uniq. Here is an example to declare a target named "server1".

```
servers:
    server1:
        login_user:     "root"
        connect_path:   "192.168.1.1:22"
```

Here is the list of possible directives inside each target object:

| Directive | Description | Example |
 --- | --- | --- 
| login_user | username used to log in. If not set, the login used to connect to the relay is used) | "root" |
| connect_path | Hostname / IP and port of remote server. | "192.168.1.1:22" |
| host_pubkeys | host public keys to identify that server. One per algorithm. | "file:data/pub/201/ssh_host_ed25519_key.pub" |
| full_name | host real name, this is just an alias to find the host | "server1.localnet.lan" |

**Declaration of users**

Users are declared in the `users` array, each entry must be uniq becasuse it is the username.

| Directive | Description | Example |
 --- | --- | --- 
| authorized_key | String containing the authorized key. | "ssh-rsa AAAAB3NzaC1yc2E....." |
| authorized_keys_file | Path to a "authorized_keys" file, listing all authorized keys for that username  | "data/users/julien.authorized_keys" |
| acl | Access list the user belongs to (see ACLs below) | "admin" |


**Access lists**

Access lists allow you to control which user can access to which servers. They are declared in the `acls` array, each entry is the name of the access list. This name is used in the `acl` directive if users.

Each access list can have two directives :
| Directive | Description | Example |
 --- | --- | --- 
| allow_servers | list of servers users are allowed to connect to. | "server1" |
| allow_groups | list of groups of servers users are allowed to connect to. | "cluster330" |


## Basic example of configuration file

```
global:
    motd_path:      "data/motd"
    log_path:       "data/logs"
    host_keys:
        - "data/keys/server_key_rsa"
    auth_type:      "ldap"
    ldap_server:    "ad.domain.local:389"
    ldap_domain:    "ad.domain.local"
    listen_path:    "0.0.0.0:22"
servers:
    vdev1.ad.domain.local:
        connect_path:   "vdev1.ad.domain.local:22"
        host_pubkeys:
            - "data/pub/vdev1/ssh_host_dsa_key.pub"
            - "data/pub/vdev1/ssh_host_ecdsa_key.pub"
            - "data/pub/vdev1/ssh_host_rsa_key.pub"
    vdev2.ad.domain.local:
        connect_path:   "vdev2.ad.domain.local:22"
        host_pubkeys:
            - "data/pub/vdev2/ssh_host_dsa_key.pub"
            - "data/pub/vdev2/ssh_host_ecdsa_key.pub"
            - "data/pub/vdev2/ssh_host_rsa_key.pub"
acls:
    development:
        allow_servers:
            - "vdev1.ad.domain.local"
            - "vdev2.ad.domain.local"
    support:
        allow_servers:
            - "vdev2.ad.domain.local"
users:
    guybrush:
        acl: "development"
    elaine:
        acl:    "support"

```

## User manual

Users can connect to the ssh bastion the same way they connect to a standard ssh server but **ONLY interactive sessions are allowed**. For example, this means that `sftp` and `ssh` are allowed, but `ssh -c` and `scp` are not. Key agent forwarding is supported.

Common ssh clients:
| method | Supported | Example of usage|
 --- | --- | --- 
| interactive SSH | yes | ssh -A guybrush@bastion.cloudprotector.test -p 2222 |
| command SSH | no (not interactive) | ssh -A guybrush@bastion.cloudprotector.test -p 2222 echo "hello world" |
| SFTP | yes | sftp -P 2222 guybrush@bastion.cloudprotector.test |
| SCP | no (not interactive) | scp guybrush@bastion.cloudprotector.test -P 2222 |

Once connected, the bastion will display a MOTD message and ask you to enter the target server name
```
Welcome to SSH Bastion Relay Agent.
This service is restricted to authorized users only.
All activities on this system are logged.

Please enter the target name (or '?' for help) 
$
```

You can enter the name of the target server or just a part of that name and press "enter". A list of possible targets will then be displayed and you will be prompted to choose among them.
```
$ isl
Select a target server :
    [  1 ] melee.island.sea
    [  2 ] monkey.island.sea
    [  3 ] dinky.island.sea
    [  4 ] scabb.island.sea
    [  5 ] plunder.island.sea
    [  6 ] blood.island.sea
    [  7 ] booty.island.sea
    [  8 ] jambalaya.island.sea
(choose target) 2
Connecting to monkey.island.sea
...
```

To leave, just logout from the remote session.

**Data transfer mode**

When connected on a remote target, you can switch to the data tranfert mode by pressing `CTRL+T` combination.
```
[root@monkey.island.sea ~]# Switching to data transfer mode
(data)$
```

This allows you to download or upload files **between the ssh bastion and the remote target only**. To retreive files on your local workstation, you must use sftp.
Here are the list of available commands in Data transfer mode:

| command | description | Example of usage|
 --- | --- | --- 
| exit | Return to the interactive command mode | exit |
| mode <scp|sftp> | Set the transfert mode with the remote target, default is sftp | mode scp |
| get <path/to/file> | download the file from the current remote directory | get ./chest.txt |
| put <path/to/file> | upload the file into the current remote directory | put ./chest.txt |

In order to upload or download files between your workstation and the ssh bastion, you can use sftp
```
sftp -P 2222 guybrush@bastion.cloudprotector.test
Connected to guybrush@bastion.cloudprotector.test.
sftp> ls
chest.txt
sftp> 
```

## Logging facilities

You can configure an external fluentbit server with the fluent_bit server option

## Build & Usage
To build, you will need the Go runtime and to build you just need to run:

```
go build
```

To test run from the command line, you can run:

```
./ssh-bastion -c "path-to-yaml-config-file"
```

## Recommended Install Procedure
```
# useradd -d /opt/ssh-bastion -s /bin/false -c "SSH-BASTION SSH Relay" -r -U -m bastion
# mkdir -p /opt/ssh-bastion/data/{logs,keys,pub,users}
# cp <ssh-bastion binary location> /opt/ssh-bastion/ssh-bastion
# cp <motd example path> /opt/ssh-bastion/data/motd
# cp <config.yaml example path> /opt/ssh-bastion/config.yaml
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_rsa_key -N '' -t rsa
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_dsa_key -N '' -t dsa
# ssh-keygen -f /opt/ssh-bastion/data/keys/ssh_host_ecdsa_key -N '' -t ecdsa
# vi /opt/ssh-bastion/config.yaml (edit config as required)
# chown -R bastion:bastion /opt/ssh-bastion
# chmod 750 /opt/ssh-bastion
# cp <systemd/ssh-bastion.service location> /etc/systemd/system/ssh-bastion.service
# systemctl daemon-reload
# systemctl enable ssh-bastion
# systemctl start ssh-bastion
```

You will then need to customize the config to match your remote servers, copying their host public keys to the data/pub folder and linking them in the config.

Your data/logs folder will probably end up taking up quite a lot of space and eating up lots of disk I/O, so with that in mind it might be worth mounting it on another disk.

## Credits
Based on [sshmuxd](https://github.com/joushou/sshmuxd) with addition of logging and LDAP auth.
