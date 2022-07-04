package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHServer struct {
	sshConfig *ssh.ServerConfig
}

func NewSSHServer() (*SSHServer, error) {
	s := &SSHServer{
		sshConfig: &ssh.ServerConfig{
			NoClientAuth:  false,
			ServerVersion: "SSH-2.0-BASTION",
			AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
				if err != nil {
					WriteAuthLog("Failed %s for user %s from %s ssh2", method, conn.User(), conn.RemoteAddr())
				} else {
					WriteAuthLog("Accepted %s for user %s from %s ssh2", method, conn.User(), conn.RemoteAddr())
				}
			},
			PasswordCallback: AuthUserPass,
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				if user, ok := config.Users[conn.User()]; !ok {
					return nil, fmt.Errorf("user not found in config for PK")
				} else {
					if len(user.AuthorizedKeyStr) > 0 {
						var authKey ssh.PublicKey
						var authKeysData = []byte(user.AuthorizedKeyStr)
						var err error
						authKey, _, _, authKeysData, err = ssh.ParseAuthorizedKey(authKeysData)
						if err != nil {
							log.Printf("Error while processing authorized key string (%s) for user (%s): %s.", user.AuthorizedKeyStr, conn.User(), err)
							return nil, fmt.Errorf("Error while processing authorized keys file.")
						}

						if (key.Type() == authKey.Type()) && (bytes.Compare(key.Marshal(), authKey.Marshal()) == 0) {
							perm := &ssh.Permissions{
								Extensions: map[string]string{
									"authType": "pk",
								},
							}
							return perm, nil
						}

					} else if len(user.AuthorizedKeysFile) > 0 {
						authKeysData, err := ioutil.ReadFile(user.AuthorizedKeysFile)
						if err != nil {
							log.Printf("Unable to read authorized keys file (%s) for user (%s): %s.", user.AuthorizedKeysFile, conn.User(), err)
							return nil, fmt.Errorf("Unable to read Authorized Keys file.")
						}

						for {
							if len(authKeysData) > 0 {
								var authKey ssh.PublicKey
								var err error
								authKey, _, _, authKeysData, err = ssh.ParseAuthorizedKey(authKeysData)
								if err != nil {
									log.Printf("Error while processing authorized keys file (%s) for user (%s): %s.", user.AuthorizedKeysFile, conn.User(), err)
									return nil, fmt.Errorf("Error while processing authorized keys file.")
								}

								if (key.Type() == authKey.Type()) && (bytes.Compare(key.Marshal(), authKey.Marshal()) == 0) {
									perm := &ssh.Permissions{
										Extensions: map[string]string{
											"authType": "pk",
										},
									}
									return perm, nil
								}
							} else {
								return nil, fmt.Errorf("No PKs Match - ACCESS DENIED")
							}
						}
					} else {
						return nil, fmt.Errorf("User has no authorized keys specified.")
					}
				}
				return nil, fmt.Errorf("An error occured while parsing authorized keys")
			},
		},
	}

	for _, k := range config.Global.BastionPrivateKeys {
		hostKey := []byte(k)
		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("Invalid SSH Host Key: %v", err)
		}

		s.sshConfig.AddHostKey(signer)
	}
	return s, nil
}

func (s *SSHServer) ListenAndServe(protocol string, addr string) error {
	l, err := net.Listen(protocol, addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

func (s *SSHServer) Serve(l net.Listener) error {
	log.Printf("Startup ok, now waiting for connections\n")
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.HandleConn(conn)
	}
}

func (s *SSHServer) HandleConn(c net.Conn) {
	startTime := time.Now()

	sshConn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		c.Close()
		return
	}
	defer WriteAuthLog("Connection closed by %s (User: %s).", sshConn.RemoteAddr(), sshConn.User())

	if sshConn.Permissions == nil || sshConn.Permissions.Extensions == nil {
		sshConn.Close()
		return
	}

	go ssh.DiscardRequests(reqs)
	newChannel := <-chans
	if newChannel == nil {
		sshConn.Close()
		return
	}

	switch newChannel.ChannelType() {
	case "session":
		s.SessionForward(startTime, sshConn, newChannel, chans)
	default:
		newChannel.Reject(ssh.UnknownChannelType, "connection flow not supported, only interactive sessions are permitted.")
	}

	sshConn.Close()
}
