package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type EntryLog struct {
	Timestamp time.Time `json:"timestamp"`
	Logger    string    `json:"logger"`
	UserName  string    `json:"user"`
	RemoteIP  string    `json:"ip"`
	Message   string    `json:"message"`
}

type LogChannel struct {
	StartTime     time.Time
	UserName      string
	RemoteIP      string
	AuthType      string
	ActualChannel ssh.Channel
	FluentBit     string
	fd            *os.File
	fd_ttyrec     *os.File
	fd_req        *os.File
	initialBuffer *bytes.Buffer
	ttyrecBuffer  *bytes.Buffer
	reqBuffer     *bytes.Buffer
	logMutex      *sync.Mutex
}

func writeTTYRecHeader(fd io.Writer, length int) {
	t := time.Now()

	tv := syscall.NsecToTimeval(t.UnixNano())

	binary.Write(fd, binary.LittleEndian, int32(tv.Sec))
	binary.Write(fd, binary.LittleEndian, int32(tv.Usec))
	binary.Write(fd, binary.LittleEndian, int32(length))
}

func NewLogChannel(startTime time.Time, channel ssh.Channel, username string, remote_ip string, auth_type string) *LogChannel {
	l := LogChannel{
		StartTime:     startTime,
		UserName:      username,
		RemoteIP:      remote_ip,
		AuthType:      auth_type,
		ActualChannel: channel,
		initialBuffer: bytes.NewBuffer([]byte{}),
		ttyrecBuffer:  bytes.NewBuffer([]byte{}),
		reqBuffer:     bytes.NewBuffer([]byte{}),
		logMutex:      &sync.Mutex{},
		FluentBit:     config.Global.FluentbitServer,
	}

	if l.FluentBit != "" {
		err := l.Log_fluentbit("daemon", fmt.Sprintf("Authentication successfull (%s), starting local session at time %s", l.AuthType, l.StartTime))
		if err != nil {
			return nil
		}
	}
	return &l
}

func (l *LogChannel) Log_fluentbit(logger string, data string) error {
	record, err := json.Marshal(EntryLog{Timestamp: time.Now(), Logger: logger, UserName: l.UserName, RemoteIP: l.RemoteIP, Message: data})
	if err != nil {
		return err
	}
	request, err := http.NewRequest("POST", l.FluentBit, bytes.NewBuffer(record))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func (l *LogChannel) RelayStart(remote_name string) error {
	var err error

	filepath := fmt.Sprintf("%s/%d/%d", config.Global.LogPath, l.StartTime.Year(), l.StartTime.Month())
	err = os.MkdirAll(filepath, 0750)
	if err != nil {
		return fmt.Errorf("Unable to create required log directory (%s): %s", filepath, err)
	}
	filename := filepath + "/" + fmt.Sprintf("ssh_log_%s_%s_%s", l.StartTime.Format(time.RFC3339), l.UserName, remote_name)

	l.logMutex.Lock()

	if l.FluentBit != "" {
		err = l.Log_fluentbit("daemon", "Starting relay logging")
		if err != nil {
			return err
		}

	} else {
		l.fd, err = os.OpenFile(filename+".txt", os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			return err
		}

		initialRecord := fmt.Sprintf(
			"[LOGGER] Timestamp: %s\n"+
				"[LOGGER] Event: Starting SSH relay session\n"+
				"[LOGGER] Username: %s\n"+
				"[LOGGER] Authenticated by: %s\n"+
				"[LOGGER] Source ip address: %s\n"+
				"\n", l.StartTime, l.UserName, l.AuthType, l.RemoteIP)
		l.fd.Write([]byte(initialRecord))

		_, err = l.initialBuffer.WriteTo(l.fd)
		if err != nil {
			return err
		}
		l.initialBuffer.Reset()
		l.initialBuffer = nil

		l.fd_req, err = os.OpenFile(filename+".sshreq", os.O_WRONLY|os.O_CREATE, 0640)
		if err != nil {
			return err
		}

		_, err = l.reqBuffer.WriteTo(l.fd_req)
		if err != nil {
			return err
		}
		l.reqBuffer.Reset()
		l.reqBuffer = nil

	}

	l.fd_ttyrec, err = os.OpenFile(filename+".ttyrec", os.O_WRONLY|os.O_CREATE, 0640)
	if err != nil {
		return err
	}

	_, err = l.ttyrecBuffer.WriteTo(l.fd_ttyrec)
	if err != nil {
		return err
	}
	l.ttyrecBuffer.Reset()
	l.ttyrecBuffer = nil

	l.logMutex.Unlock()

	return nil
}

func (l *LogChannel) Read(data []byte) (int, error) {
	return l.ActualChannel.Read(data)
}

func (l *LogChannel) Write(data []byte) (int, error) {
	l.logMutex.Lock()
	if len(data) > 0 {

		if l.FluentBit != "" {
			err := l.Log_fluentbit("session", bytes.NewBuffer(data).String())
			if err != nil {
				return 0, err
			}
		} else {
			if l.fd != nil {
				l.fd.Write(data)
			} else {
				l.initialBuffer.Write(data)
			}
		}

		if l.fd_ttyrec != nil {
			writeTTYRecHeader(l.fd_ttyrec, len(data))
			l.fd_ttyrec.Write(data)
		} else {
			writeTTYRecHeader(l.ttyrecBuffer, len(data))
			l.ttyrecBuffer.Write(data)
		}
	}
	l.logMutex.Unlock()

	return l.ActualChannel.Write(data)
}

func (l *LogChannel) Close() error {
	EndTime := time.Now()
	Duration := EndTime.Sub(l.StartTime)

	if l.FluentBit != "" {
		err := l.Log_fluentbit("daemon", fmt.Sprintf("Closing session, duration=[%s]", Duration))
		if err != nil {
			return err
		}
	} else {
		FinalRecord := fmt.Sprintf(
			"\n"+
				"[LOGGER] Timestamp: %s\n"+
				"[LOGGER] Event: Closing SSH session\n"+
				"[LOGGER] Duration: %s\n"+
				"\n", EndTime, Duration)
		l.fd.Write([]byte(FinalRecord))

		if l.fd != nil {
			l.fd.Close()
		}

		if l.fd_req != nil {
			l.fd_req.Close()
		}

	}

	if l.fd_ttyrec != nil {
		l.fd_ttyrec.Close()
	}

	return l.ActualChannel.Close()
}

func (l *LogChannel) LogRequest(r *ssh.Request) {
	if l.FluentBit != "" {
		l.Log_fluentbit("request", fmt.Sprintf("Request Type: %s\n"+
			"Want Reply: %t\n"+
			"Payload: %#v\r\n", r.Type, r.WantReply, r.Payload))
	} else {
		logLine := fmt.Sprintf("%s: Request Type - %s - Want Reply: %t - Payload: %#v\r\n", time.Now().Format(time.RFC3339), r.Type, r.WantReply, r.Payload)
		if l.fd_req != nil {
			l.fd_req.Write([]byte(logLine))
		} else {
			l.reqBuffer.Write([]byte(logLine))
		}
	}
}

func (l *LogChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return l.ActualChannel.SendRequest(name, wantReply, payload)
}
