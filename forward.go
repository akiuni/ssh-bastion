package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

type rw struct {
	io.Reader
	io.Writer
}

func SecureConvertPayloadToString(Payload []byte) (string, error) {

	if len(Payload) < 4 {
		return "", nil
	}
	payload_len := binary.BigEndian.Uint32(Payload[:4])
	if payload_len > 32*1024 {
		return "", nil
	}
	if len(Payload) < (int(payload_len) - 4) {
		payload_len = uint32(len(Payload) - 4)
	}
	payload_str := string(Payload[4:(payload_len + 4)])
	return payload_str, nil

}

func (s *SSHServer) SessionForward(startTime time.Time, sshConn *ssh.ServerConn, newChannel ssh.NewChannel, chans <-chan ssh.NewChannel) {
	rawsesschan, sessReqs, err := newChannel.Accept()
	if err != nil {
		sshConn.Close()
		return
	}
	defer sshConn.Close()

	sesschan := NewLogChannel(startTime, rawsesschan, sshConn.User(), sshConn.RemoteAddr().String(), sshConn.Permissions.Extensions["authType"])

	go func() {
		for newChannel = range chans {
			if newChannel == nil {
				return
			}
			newChannel.Reject(ssh.Prohibited, "remote server denied channel request")
			continue
		}
	}()

	var agentForwarding bool = false
	var startInteractiveSession bool = false

	maskedReqs := make(chan *ssh.Request, 5)

	go func() {
		for req := range sessReqs {

			payload_str, err := SecureConvertPayloadToString(req.Payload)
			if err != nil {
				log.Println("Too many data received, aborting the session")
				sesschan.Close()
				return
			}
			sesschan.LogRequest(req)
			if (req.Type == "auth-agent-req@openssh.com") && config.Global.AllowAgentForwarding {
				agentForwarding = true
				if req.WantReply {
					req.Reply(true, []byte{})
				}
				continue
			} else if (req.Type == "pty-req") && (req.WantReply) {
				if startInteractiveSession {
					req.Reply(true, []byte{})
					req.WantReply = false
				} else {
					startInteractiveSession = true
				}
			} else if (req.Type == "shell") && (req.WantReply) {
				if startInteractiveSession {
					req.Reply(true, []byte{})
					req.WantReply = false
				} else {
					startInteractiveSession = true
				}

			} else if (req.Type == "exec") && (req.WantReply) {
				req.Reply(true, []byte{})
				req.WantReply = false
			} else if (req.Type == "subsystem") && (req.WantReply) {
				if startInteractiveSession {
					req.Reply(true, []byte{})
					req.WantReply = false
				} else {

					if payload_str == "sftp" {
						fs, err := createHandler(config.Global.StoragePath, sesschan)
						if err != nil {
							log.Printf("Unable to get user home: %v\n", err)
							sesschan.Close()
							return
						}
						server := sftp.NewRequestServer(sesschan, fs)
						if err != nil {
							log.Printf("Error while starting sftp server: %v\n", err)
							sesschan.Close()
							return
						}

						if err := server.Serve(); err == io.EOF {
							server.Close()
							log.Print("sftp client exited session.")
						} else if err != nil {
							log.Printf("sftp server completed with error: %v\n", err)
						}
						sesschan.Close()
						return
					}
				}
				return
			}
			maskedReqs <- req
		}
	}()

	for {
		if startInteractiveSession {
			break
		}
	}

	fmt.Fprintf(sesschan, "%s\r\n", GetMOTD())

	var remote SSHConfigServer
	var remote_name string
	var remote_action string
	if user, ok := config.Users[sshConn.User()]; !ok {
		fmt.Fprintf(sesschan, "User has no permitted remote hosts.\r\n")
		sesschan.Close()
		return
	} else {
		if acl, ok := config.ACLs[user.ACL]; !ok {
			fmt.Fprintf(sesschan, "Error processing server selection (Invalid ACL).\r\n")
			log.Printf("Invalid ACL detected for user %s.", sshConn.User())
			sesschan.Close()
			return
		} else {
			cmd, svr, err := InteractiveSelection(sesschan, "Please enter the target name (or '?' for help) ", acl.AllowedServers)
			if err != nil {
				fmt.Fprintf(sesschan, "Error processing server selection.\r\n")
				sesschan.Close()
				return
			}

			if server, ok := config.Servers[svr]; !ok {
				fmt.Fprintf(sesschan, "Incorrectly Configured Server Selected.\r\n")
				sesschan.Close()
				return
			} else if cmd != "session" {
				fmt.Fprintf(sesschan, "Incorrectly Action Selected.\r\n")
				sesschan.Close()
				return
			} else {
				remote_name = svr
				remote = server
				remote_action = cmd
			}
		}
	}

	err = sesschan.RelayStart(remote_name)

	if err != nil {
		fmt.Fprintf(sesschan, "Failed to Initialize Session.\r\n")
		sesschan.Close()
		return
	}
	WriteAuthLog("Connecting to remote for relay (%s) by %s from %s.", remote.ConnectPath, sshConn.User(), sshConn.RemoteAddr())
	fmt.Fprintf(sesschan, "Connecting to %s\r\n", remote_name)

	timeout, _ := time.ParseDuration("30s")
	if len(config.Global.ConnectTimeout) > 0 {
		timeout, err = time.ParseDuration(config.Global.ConnectTimeout)
		if err != nil {
			log.Printf("Ignored invalid timeout in configuration: %v.\r\n", err)
		}
	}

	var clientConfig *ssh.ClientConfig

	clientConfig = &ssh.ClientConfig{
		User: sshConn.User(),
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (secret string, err error) {
				if secret, ok := sshConn.Permissions.Extensions["password"]; ok && config.Global.PassPassword {
					return secret, nil
				} else {
					t := terminal.NewTerminal(sesschan, "")
					s, err := t.ReadPassword(fmt.Sprintf("%s@%s password: ", clientConfig.User, remote_name))
					return s, err
				}
			}),
		},
		HostKeyCallback: func(hostname string, remote_addr net.Addr, key ssh.PublicKey) error {
			for _, k := range remote.HostPubKeys {
				hostKeyData := []byte(k)
				hostKey, _, _, _, err := ssh.ParseAuthorizedKey(hostKeyData)
				if err != nil {
					continue
				}

				if (key.Type() == hostKey.Type()) && (bytes.Compare(key.Marshal(), hostKey.Marshal()) == 0) {
					return nil
				}
			}
			WriteAuthLog("Host key validation failed for remote %s by user %s from %s.", remote.ConnectPath, sshConn.User(), remote_addr)
			return fmt.Errorf("HOST KEY VALIDATION FAILED - POSSIBLE MITM BETWEEN RELAY AND REMOTE")
		},
		Timeout: timeout,
	}

	if config.Global.IgnoreHostPubKeys {
		clientConfig.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	if config.Global.AuthWithBastionKeys {
		for _, k := range config.Global.BastionPrivateKeys {
			key := []byte(k)
			signer, err := ssh.ParsePrivateKey(key)
			if err == nil {
				clientConfig.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, clientConfig.Auth...)
			}
		}
	}

	if len(remote.LoginUser) > 0 {
		clientConfig.User = remote.LoginUser
	}

	if agentForwarding {
		agentChan, agentReqs, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)

		if err == nil {
			defer agentChan.Close()

			go ssh.DiscardRequests(agentReqs)
			ag := agent.NewClient(agentChan)
			clientConfig.Auth = append([]ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)}, clientConfig.Auth...)
		}

	}

	client, err := ssh.Dial("tcp", remote.ConnectPath, clientConfig)
	if err != nil {
		fmt.Fprintf(sesschan, "Connect failed: %v\r\n", err)
		sesschan.Close()
		return
	}
	defer client.Close()

	if remote_action == "session" {
		channel2, reqs2, err := client.OpenChannel("session", []byte{})
		if err != nil {
			fmt.Fprintf(sesschan, "Remote session setup failed: %v\r\n", err)
			sesschan.Close()
			return
		}
		WriteAuthLog("Connected to remote for relay (%s) by %s from %s.", remote.ConnectPath, sshConn.User(), sshConn.RemoteAddr())
		defer WriteAuthLog("Disconnected from remote for relay (%s) by %s from %s.", remote.ConnectPath, sshConn.User(), sshConn.RemoteAddr())

		proxy(maskedReqs, reqs2, sesschan, channel2, client)
	}

}

type readCloser struct {
	io.Reader
	io.Closer
}

func proxy(reqs1, reqs2 <-chan *ssh.Request, channel1 *LogChannel, channel2 ssh.Channel, client *ssh.Client) {

	cmd_readcloser := readCloser{io.TeeReader(channel1, channel2), channel1}

	var closer sync.Once
	closeFunc := func() {
		channel1.Close()
		channel2.Close()
		cmd_readcloser.Close()
	}
	defer closer.Do(closeFunc)

	closerChan := make(chan bool, 1)

	go func() {
		io.Copy(channel1, channel2)
		closerChan <- true
	}()

	go func() {
		buf := make([]byte, 1)
		for {
			_, err := io.ReadFull(cmd_readcloser, buf)
			if err != nil {
				break
			}
			if buf[0] == '\x14' {
				fmt.Fprintf(channel1, "Switching to data transfer mode\r\n")

				InteractiveDataSession(channel1, client)
				fmt.Fprintf(channel2, "\r\n")
			}
		}
	}()

	for {
		select {
		case req := <-reqs1:
			if req == nil {
				return
			}
			b, err := channel2.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case req := <-reqs2:
			if req == nil {
				return
			}
			b, err := channel1.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			req.Reply(b, nil)
		case <-closerChan:
			return
		}
	}
}
