package main

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/sftp"
)

func createHandler(base_path string, channel *LogChannel) (sftp.Handlers, error) {

	chroot := base_path + "/" + channel.UserName
	_, err := os.Stat(chroot)
	if os.IsNotExist(err) {
		err = os.Mkdir(chroot, 0700)
	}
	if err != nil {
		return sftp.Handlers{
			FileGet:  nil,
			FilePut:  nil,
			FileCmd:  nil,
			FileList: nil,
		}, err
	}

	p := FileSystem{
		ReadOnly: false,
		HasDiskSpace: func(fs *FileSystem) bool {
			return true
		},
		PathValidator: func(fs *FileSystem, p string) (string, error) {
			join := path.Join(chroot, p)
			clean := path.Clean(chroot)
			if strings.HasPrefix(join, clean) {
				return join, nil
			}
			return "", errors.New("invalid path outside the configured directory was provided")
		},
	}

	return sftp.Handlers{
		FileGet:  &p,
		FilePut:  &p,
		FileCmd:  &p,
		FileList: &p,
	}, nil
}

type FileSystem struct {
	ReadOnly bool

	PathValidator func(fs *FileSystem, p string) (string, error)
	HasDiskSpace  func(fs *FileSystem) bool

	lock sync.Mutex
}

func (fs *FileSystem) buildPath(p string) (string, error) {
	return fs.PathValidator(fs, p)
}

const (
	PermissionFileRead        = "file.read"
	PermissionFileReadContent = "file.read-content"
	PermissionFileCreate      = "file.create"
	PermissionFileUpdate      = "file.update"
	PermissionFileDelete      = "file.delete"
)

func (fs *FileSystem) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	p, err := fs.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	fs.lock.Lock()
	defer fs.lock.Unlock()

	if _, err := os.Stat(p); os.IsNotExist(err) {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	file, err := os.Open(p)
	if err != nil {
		log.Printf("could not open file for reading %v\n", err)
		return nil, sftp.ErrSshFxFailure
	}

	return file, nil
}

func (fs *FileSystem) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	if fs.ReadOnly {
		return nil, sftp.ErrSshFxOpUnsupported
	}

	p, err := fs.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	if !fs.HasDiskSpace(fs) {
		return nil, ErrSSHQuotaExceeded
	}

	fs.lock.Lock()
	defer fs.lock.Unlock()

	stat, statErr := os.Stat(p)
	if os.IsNotExist(statErr) {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			log.Printf("error making path for file %v\n", err)
			return nil, sftp.ErrSshFxFailure
		}

		file, err := os.Create(p)
		if err != nil {
			log.Printf("error creating file: %v\n", err)
			return nil, sftp.ErrSshFxFailure
		}

		return file, nil
	}

	if statErr != nil {
		log.Printf("error : %v\n", err)
		return nil, sftp.ErrSshFxFailure
	}

	if stat.IsDir() {
		log.Printf("warning : %v\n", err)
		return nil, sftp.ErrSshFxOpUnsupported
	}

	file, err := os.Create(p)
	if err != nil {
		log.Printf("error : %v\n", err)
		return nil, sftp.ErrSshFxFailure
	}

	return file, nil
}

func (fs *FileSystem) Filecmd(request *sftp.Request) error {
	if fs.ReadOnly {
		return sftp.ErrSshFxOpUnsupported
	}

	p, err := fs.buildPath(request.Filepath)
	if err != nil {
		return sftp.ErrSshFxNoSuchFile
	}

	var target string
	if request.Target != "" {
		target, err = fs.buildPath(request.Target)
		if err != nil {
			return sftp.ErrSshFxOpUnsupported
		}
	}

	switch request.Method {
	case "Setstat":
		var mode os.FileMode = 0600
		if request.Attributes().FileMode().Perm() != 0000 {
			mode = request.Attributes().FileMode().Perm()
		}

		if request.Attributes().FileMode().IsDir() {
			mode = 0755
		}

		if err := os.Chmod(p, mode); err != nil {
			log.Printf("error : %v\n", err)
			return sftp.ErrSshFxFailure
		}
		return nil
	case "Rename":
		if err := os.Rename(p, target); err != nil {
			log.Printf("error : %v\n", err)
			return sftp.ErrSshFxFailure
		}

		break
	case "Rmdir":
		if err := os.RemoveAll(p); err != nil {
			log.Printf("error : %v\n", err)
			return sftp.ErrSshFxFailure
		}

		return sftp.ErrSshFxOk
	case "Mkdir":
		if err := os.MkdirAll(p, 0755); err != nil {
			log.Printf("error : %v\n", err)
			return sftp.ErrSshFxFailure
		}

		break
	case "Symlink":
		if err := os.Symlink(p, target); err != nil {
			log.Printf("error : %v\n", err)
			return sftp.ErrSshFxFailure
		}

		break
	case "Remove":
		if err := os.Remove(p); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("error : %v\n", err)
			}
			return sftp.ErrSshFxFailure
		}

		return sftp.ErrSshFxOk
	default:
		return sftp.ErrSshFxOpUnsupported
	}

	return sftp.ErrSshFxOk
}

func (fs *FileSystem) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	p, err := fs.buildPath(request.Filepath)
	if err != nil {
		return nil, sftp.ErrSshFxNoSuchFile
	}

	switch request.Method {
	case "List":
		files, err := ioutil.ReadDir(p)
		if err != nil {
			log.Printf("error : %v\n", err)
			return nil, sftp.ErrSshFxFailure
		}

		return ListerAt(files), nil
	case "Stat":
		s, err := os.Stat(p)
		if os.IsNotExist(err) {
			return nil, sftp.ErrSshFxNoSuchFile
		} else if err != nil {
			log.Printf("error : %v\n", err)
			return nil, sftp.ErrSshFxFailure
		}

		return ListerAt([]os.FileInfo{s}), nil
	default:
		return nil, sftp.ErrSshFxOpUnsupported
	}
}
