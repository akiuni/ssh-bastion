package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type datasession struct {
	client *ssh.Client
	mode   string
}

func New(client *ssh.Client) (result *datasession, err error) {
	result = &datasession{
		client: client,
		mode:   "sftp",
	}

	return
}

func (c *datasession) newSession() (session *ssh.Session, err error) {
	log.Println("opening new ssh session")
	if c.client == nil {
		err = errors.New("client not available")
	} else {
		session, err = c.client.NewSession()
	}

	return session, nil
}

func (c *datasession) Download(path string, output io.Writer) error {
	if c.mode == "scp" {
		log.Println("starting scp download")
		return c.scpDownloadSession(path, output)
	}
	log.Println("starting sftp download")
	return c.sftpDownloadSession(path, output)
}

func (c *datasession) Upload(path string, input io.Reader, fi *os.FileInfo) error {
	if c.mode == "scp" {
		log.Println("starting scp upload")
		return c.scpUploadSession(path, input, fi)
	}
	log.Println("starting sftp upload")
	return c.sftpUploadSession(path, input, fi)
}

func (c *datasession) scpDownloadSession(path string, output io.Writer) error {
	scpFunc := func(w io.Writer, stdoutR *bufio.Reader) error {
		fmt.Fprint(w, "\x00")

		fi, err := stdoutR.ReadString('\n')
		if err != nil {
			return err
		}

		if len(fi) < 0 {
			return fmt.Errorf("empty response from server")
		}

		switch fi[0] {
		case '\x01', '\x02':
			return fmt.Errorf("%s", fi[1:len(fi)])
		case 'C':
		case 'D':
			return fmt.Errorf("remote file is directory")
		default:
			return fmt.Errorf("unexpected server response (%x)", fi[0])
		}

		var mode string
		var size int64

		n, err := fmt.Sscanf(fi, "%6s %d ", &mode, &size)
		if err != nil || n != 2 {
			return fmt.Errorf("can't parse server response (%s)", fi)
		}
		if size < 0 {
			return fmt.Errorf("negative file size")
		}

		fmt.Fprint(w, "\x00")

		if _, err := io.CopyN(output, stdoutR, size); err != nil {
			return err
		}

		fmt.Fprint(w, "\x00")

		if err := checkSCPStatus(stdoutR); err != nil {
			return err
		}

		return nil
	}

	if strings.Index(path, " ") == -1 {
		return c.scpSession("scp -vf "+path, scpFunc)
	}
	return c.scpSession("scp -vf "+strconv.Quote(path), scpFunc)
}

func (c *datasession) scpUploadSession(path string, input io.Reader, fi *os.FileInfo) error {

	target_dir := filepath.Dir(path)
	target_file := filepath.Base(path)
	target_dir = filepath.ToSlash(target_dir)

	scpFunc := func(w io.Writer, stdoutR *bufio.Reader) error {
		return scpUploadFile(target_file, input, w, stdoutR, fi)
	}

	return c.scpSession("scp -vt "+target_dir, scpFunc)
}

func (c *datasession) scpSession(scpCommand string, f func(io.Writer, *bufio.Reader) error) error {
	session, err := c.newSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdinW, err := session.StdinPipe()
	if err != nil {
		return err
	}

	defer func() {
		if stdinW != nil {
			stdinW.Close()
		}
	}()

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stdoutR := bufio.NewReader(stdoutPipe)

	stderr := new(bytes.Buffer)
	session.Stderr = stderr

	log.Println("Starting remote scp process: ", scpCommand)
	if err := session.Start(scpCommand); err != nil {
		return err
	}

	log.Println("Started SCP session, beginning transfers...")
	if err := f(stdinW, stdoutR); err != nil && err != io.EOF {
		return err
	}

	log.Println("SCP session complete, closing stdin pipe.")
	stdinW.Close()
	stdinW = nil

	log.Println("Waiting for SSH session to complete.")
	err = session.Wait()
	if err != nil {
		if exitErr, ok := err.(*ssh.ExitError); ok {
			log.Printf("non-zero exit status: %d", exitErr.ExitStatus())

			if exitErr.ExitStatus() == 127 {
				return errors.New(
					"SCP failed to start. This usually means that SCP is not\n" +
						"properly installed on the remote system.")
			}
		}

		return err
	}

	log.Printf("scp stderr (length %d): %s", stderr.Len(), stderr.String())
	return nil
}

func checkSCPStatus(r *bufio.Reader) error {
	code, err := r.ReadByte()
	if err != nil {
		return err
	}

	if code != 0 {
		message, _, err := r.ReadLine()
		if err != nil {
			return fmt.Errorf("Error reading error message: %s", err)
		}

		return errors.New(string(message))
	}

	return nil
}

func scpDownloadFile(dst string, src io.Reader, size int64, mode os.FileMode) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(f, src, size); err != nil {
		return err
	}
	return nil
}

func scpUploadFile(dst string, src io.Reader, w io.Writer, r *bufio.Reader, fi *os.FileInfo) error {
	var mode os.FileMode
	var size int64

	if fi != nil && (*fi).Mode().IsRegular() {
		mode = (*fi).Mode().Perm()
		size = (*fi).Size()
	} else {
		tf, err := ioutil.TempFile("", "packer-upload")
		if err != nil {
			return fmt.Errorf("Error creating temporary file for upload: %s", err)
		}
		defer os.Remove(tf.Name())
		defer tf.Close()

		mode = 0644

		log.Println("Copying input data into temporary file so we can read the length")
		if _, err := io.Copy(tf, src); err != nil {
			return err
		}

		if err := tf.Sync(); err != nil {
			return fmt.Errorf("Error creating temporary file for upload: %s", err)
		}

		if _, err := tf.Seek(0, 0); err != nil {
			return fmt.Errorf("Error creating temporary file for upload: %s", err)
		}

		tfi, err := tf.Stat()
		if err != nil {
			return fmt.Errorf("Error creating temporary file for upload: %s", err)
		}

		size = tfi.Size()
		src = tf
	}

	perms := fmt.Sprintf("C%04o", mode)

	fmt.Fprintln(w, perms, size, dst)
	if err := checkSCPStatus(r); err != nil {
		return err
	}

	if _, err := io.CopyN(w, src, size); err != nil {
		return err
	}

	fmt.Fprint(w, "\x00")
	if err := checkSCPStatus(r); err != nil {
		return err
	}

	return nil
}

func (c *datasession) sftpDownloadSession(path string, output io.Writer) error {
	sftpFunc := func(client *sftp.Client) error {
		f, err := client.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if _, err = io.Copy(output, f); err != nil {
			return err
		}

		return nil
	}

	return c.sftpSession(sftpFunc)
}

func (c *datasession) sftpSession(f func(*sftp.Client) error) error {
	client, err := c.newSftpClient()
	if err != nil {
		return err
	}
	defer client.Close()

	return f(client)
}

func (c *datasession) newSftpClient() (*sftp.Client, error) {
	session, err := c.newSession()
	if err != nil {
		return nil, err
	}

	if err := session.RequestSubsystem("sftp"); err != nil {
		return nil, err
	}

	pw, err := session.StdinPipe()
	if err != nil {
		return nil, err
	}
	pr, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	return sftp.NewClientPipe(pr, pw)
}

func (c *datasession) sftpUploadSession(path string, input io.Reader, fi *os.FileInfo) error {
	sftpFunc := func(client *sftp.Client) error {
		return sftpUploadFile(path, input, client, fi)
	}

	return c.sftpSession(sftpFunc)
}

func sftpUploadFile(path string, input io.Reader, client *sftp.Client, fi *os.FileInfo) error {

	f, err := client.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = io.Copy(f, input); err != nil {
		return err
	}

	if fi != nil && (*fi).Mode().IsRegular() {
		mode := (*fi).Mode().Perm()
		err = client.Chmod(path, mode)
		if err != nil {
			return err
		}
	}

	return nil
}

func controlFile(file_name string) (string, int64, error) {

	input, err := os.OpenFile(file_name, syscall.O_RDONLY, 0600)
	if err != nil {
		return "", -1, err
	}
	defer input.Close()

	h := md5.New()
	n, err := io.Copy(h, input)

	if err != nil {
		return "", -1, err
	}
	md5str := fmt.Sprintf("%x", h.Sum(nil))

	s, err := input.Stat()
	if err != nil {
		return md5str, -1, err
	}
	if n != s.Size() {
		return md5str, -1, errors.New("Bad file size")
	}

	return md5str, n, nil
}
