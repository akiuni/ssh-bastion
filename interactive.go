package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"syscall"
	"unicode"

	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func interactiveAutocompletion(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	if unicode.IsDigit(key) || (strings.IndexRune("yYoOnN", key) != -1) {
		return string(key), 1, true
	} else {
		return line, pos, true
	}
}

func InteractiveDataSession(c *LogChannel, client *ssh.Client) error {

	var d datasession
	d.client = client
	d.mode = "sftp"

	data_path := filepath.Clean(config.Global.StoragePath + "/" + c.UserName)
	os.MkdirAll(data_path, 0700)

	for {
		t := terminal.NewTerminal(c, "(data)$ ")
		cmd, err := t.ReadLine()
		if err != nil {
			return err
		}
		cmdTab := strings.Split(cmd, " ")

		switch cmdTab[0] {
		case "":
			break
		case "help", "?":
			fmt.Fprintf(c, "\r\nUsage: TODO\r\n")
			break
		case "exit", "quit":
			fmt.Fprintf(c, "Exiting...")
			return nil
		case "mode":
			if len(cmdTab) != 2 {
				fmt.Fprintf(c, "Missing mode (sftp or scp)\r\n")
				break
			}
			if (cmdTab[1] == "scp") || (cmdTab[1] == "sftp") {
				d.mode = cmdTab[1]
				fmt.Fprintf(c, "Transfer mode set to %s\r\n", cmdTab[1])
			} else {
				fmt.Fprintf(c, "Unknown transfer mode\r\n")
			}
			break
		case "get":
			if len(cmdTab) != 2 {
				fmt.Fprintf(c, "Missing file name\r\n")
				break
			}
			file_name := filepath.Clean(cmdTab[1])
			local_filename := data_path + filepath.Clean("/"+path.Base(file_name))
			fmt.Fprintf(c, "Downloading %s\r\n", file_name)

			w, err := os.OpenFile(local_filename, syscall.O_WRONLY|syscall.O_CREAT, 0600)
			if err != nil {
				fmt.Fprintf(c, "Error writing target file : %v\r\n", err)
				break
			}
			defer w.Close()

			err = d.Download(file_name, w)
			if err != nil {
				fmt.Fprintf(c, "Error downloading file : %v\r\n", err)
				break
			}

			w.Close()
			file_md5, file_size, err := controlFile(local_filename)
			if err != nil {
				if c.FluentBit != "" {
					c.Log_fluentbit("data_transfer", fmt.Sprintf("File download: Failed security controls\n"+
						"Name: %s\n"+
						"Size: %d\n"+
						"MD5 sum: %s\n"+
						"Error: %v"+
						"\n", file_name, file_size, file_md5, err))
				} else {
					DownloadLogRecord := fmt.Sprintf(
						"[LOGGER] File download: Failed security controls\n"+
							"[LOGGER] Name: %s\n"+
							"[LOGGER] Size: %d\n"+
							"[LOGGER] MD5 sum: %s\n"+
							"[LOGGER] Error: %v"+
							"\n", file_name, file_size, file_md5, err)
					c.fd.Write([]byte(DownloadLogRecord))
				}
				fmt.Fprintf(c, "Downloaded aborted (%v)\r\n", err)
				os.Remove(local_filename)
				break
			}
			if c.FluentBit != "" {
				c.Log_fluentbit("data_transfer", fmt.Sprintf("File download: Success\n"+
					"Name: %s\n"+
					"Size: %d\n"+
					"MD5 sum: %s\n"+
					"\n", file_name, file_size, file_md5))
			} else {
				DownloadLogRecord := fmt.Sprintf(
					"[LOGGER] File download: Success\n"+
						"[LOGGER] Name: %s\n"+
						"[LOGGER] Size: %d\n"+
						"[LOGGER] MD5 sum: %s\n"+
						"\n", file_name, file_size, file_md5)
				c.fd.Write([]byte(DownloadLogRecord))
			}
			fmt.Fprintf(c, "Done\r\n")

			break
		case "put":
			if len(cmdTab) != 2 {
				fmt.Fprintf(c, "Missing file name\r\n")
				break
			}
			file_name := data_path + filepath.Clean("/"+cmdTab[1])
			fmt.Fprintf(c, "Uploading %s\r\n", file_name)

			file_md5, file_size, err := controlFile(file_name)
			if err != nil {
				if c.FluentBit != "" {
					c.Log_fluentbit("data_transfer", fmt.Sprintf("File upload: Failed security controls\n"+
						"Name: %s\n"+
						"Size: %d\n"+
						"MD5 sum: %s\n"+
						"Error: %v"+
						"\n", file_name, file_size, file_md5, err))
				} else {
					UploadLogRecord := fmt.Sprintf(
						"[LOGGER] File upload: Failed security controls\n"+
							"[LOGGER] Name: %s\n"+
							"[LOGGER] Size: %d\n"+
							"[LOGGER] MD5 sum: %s\n"+
							"[LOGGER] Error: %v"+
							"\n", file_name, file_size, file_md5, err)
					c.fd.Write([]byte(UploadLogRecord))
				}
				fmt.Fprintf(c, "Upload aborted (%v)\r\n", err)
				os.Remove(file_name)
				break
			}

			r, err := os.OpenFile(file_name, syscall.O_RDONLY, 0600)
			if err != nil {
				fmt.Fprintf(c, "Error reading source file : %v\r\n", err)
				break
			}
			defer r.Close()

			s, err := r.Stat()
			if err != nil {
				fmt.Fprintf(c, "Error stat reading source file : %v\r\n", err)
				break
			}

			err = d.Upload("./"+path.Base(file_name), r, &s)
			if err != nil {
				fmt.Fprintf(c, "Error uploading file : %v\r\n", err)
				break
			}

			if c.FluentBit != "" {
				c.Log_fluentbit("data_transfer", fmt.Sprintf("File upload: Success\n"+
					"Name: %s\n"+
					"Size: %d\n"+
					"MD5 sum: %s\n"+
					"\n", file_name, file_size, file_md5))
			} else {
				UploadLogRecord := fmt.Sprintf(
					"[LOGGER] File upload: Success\n"+
						"[LOGGER] Name: %s\n"+
						"[LOGGER] Size: %d\n"+
						"[LOGGER] MD5 sum: %s\n"+
						"\n", file_name, file_size, file_md5)
				c.fd.Write([]byte(UploadLogRecord))
			}
			fmt.Fprintf(c, "Done\r\n")
			break
		}

	}

}

func InteractiveSelection(c io.ReadWriter, prompt string, choices []string) (string, string, error) {

	fmt.Fprintf(c, "%s\r\n", prompt)

	selected_mode := "session"

	for {
		t := terminal.NewTerminal(c, "$ ")
		cmd, err := t.ReadLine()
		if err != nil {
			return "", "", err
		}
		cmdTab := strings.Split(cmd, " ")

		switch cmdTab[0] {
		case "":
			break
		case "help", "?":
			fmt.Fprintf(c, "\r\nUsage:\r\n"+
				"\tEnter a keyword to locate the server you want to connect to.\r\n"+
				"\tA list of possible targets will be displayed, enter the full\r\n"+
				"\tname to start the session.\r\n"+
				"\r\n"+
				"Type 'exit' or 'quit' to leave the session\r\n"+
				"\r\n")
			break
		case "exit", "quit":
			fmt.Fprintf(c, "Exiting...\r\n")
			return "", "", err
		default:
			suggestions := []string{}
			i_suggestion := 0
			for i := 0; i < len(choices); i++ {
				if strings.Index(choices[i], cmdTab[0]) != -1 {
					suggestions = append(suggestions, choices[i])
					i_suggestion++
					if i_suggestion > 10 {
						break
					}
				}
			}
			if i_suggestion == 0 {
				fmt.Fprintf(c, "No server found\r\n")
			} else if i_suggestion > 10 {
				fmt.Fprintf(c, "Too many results\r\n")
			} else if i_suggestion == 1 {
				fmt.Fprintf(c, "Connect to %s ? \r\n", suggestions[0])
				t.SetPrompt("(y/n) ")
				t.AutoCompleteCallback = interactiveAutocompletion
				sel, err := t.ReadLine()
				if err != nil {
					break
				}
				sel = strings.ToLower(sel)
				if (sel == "y") || (sel == "o") {
					return selected_mode, suggestions[0], err
				}
				break
			} else {
				fmt.Fprintf(c, "Select a target server :\r\n")
				for i, v := range suggestions {
					fmt.Fprintf(c, "    [ %2d ] %s\r\n", i+1, v)
				}
				t.SetPrompt("(choose target) ")
				t.AutoCompleteCallback = interactiveAutocompletion
				sel, err := t.ReadLine()
				if err != nil {
					break
				}
				i, err := strconv.Atoi(sel)
				if err != nil {
					break
				}
				if (i < 0) || (i > len(suggestions)) {
					fmt.Fprintf(c, "Invalid target\r\n")
					break
				} else {
					return selected_mode, suggestions[(i - 1)], err
				}
			}
			break
		}

	}
}
