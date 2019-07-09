package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"syscall"
)

func main() {
	keyPathPtr := flag.String("key", "", "SSH key path")
	serverNamePtr := flag.String("host", "", "Hostname to check")
	serverPortPrt := flag.Int("port", 22, "Port ssh runs on")
	usernamePtr := flag.String("user", "", "Username to use")

	flag.Parse()

	var username string
	if usernamePtr == nil || *usernamePtr == "" {
		var exists bool
		username, exists = os.LookupEnv("USER")
		if !exists {
			log.Fatalf("Username has to be set either as --username or in $USER")
			return
		}
	} else {
		username = *usernamePtr
	}

	var keyPath string
	if keyPathPtr == nil || *keyPathPtr == "" {
		homeDirectory, exists := os.LookupEnv("HOME")
		if !exists {
			log.Fatalf("SSH key path has to be set")
			return
		}
		keyPath = path.Join(homeDirectory, ".ssh", "id_rsa")
	} else {
		keyPath = *keyPathPtr
	}

	if serverNamePtr == nil || *serverNamePtr == "" {
		log.Fatalf("Host has to be set")
		return
	}

	sshConfig := createSshConfig(username, keyPath)

	commands := make(chan string, 10)
	results := make(chan string, 10)

	go runSshCommands(sshConfig, fmt.Sprintf("%s:%d", *serverNamePtr, *serverPortPrt), commands, results)

	commands <- "ls /etc/nginx/sites-enabled/"
	listString := <-results
	list := strings.Fields(listString)

	for _, project := range list {
		if project == "default" {
			continue
		}

		commands <- fmt.Sprintf("cat /etc/nginx/sites-enabled/%s", project)
		result := <-results

		parts := strings.Fields(result)
		serverName := ""
		for i := 0; i < len(parts)-1 && serverName == ""; i++ {
			if strings.ToLower(parts[i]) == "server_name" {
				serverName = parts[i+1]
				if len(serverName) > 0 && serverName[len(serverName)-1] == ';' {
					serverName = serverName[:len(serverName)-1]
				}
			}
		}

		resp, err := http.Get(fmt.Sprintf("https://%s/", serverName))
		if err != nil {
			fmt.Printf("%s: %s -> ERROR %v\n", project, serverName, err)
		} else {
			fmt.Printf("%s: %s -> %d\n", project, serverName, resp.StatusCode)
		}
	}

	close(commands)

}

func createSshConfig(username string, keyPath string) *ssh.ClientConfig {
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	key = decryptKey(key)

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	return &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // todo: fix this?
	}
}

func runSshCommands(config *ssh.ClientConfig, hostname string, in chan string, out chan string) {
	// Connect to the remote server and perform the SSH handshake.
	client, err := ssh.Dial("tcp", hostname, config)
	if err != nil {
		log.Fatalf("unable to connect: %v", err)
	}
	defer client.Close()

	for command := range in {
		// Each ClientConn can support multiple interactive sessions,
		// represented by a Session.
		session, err := client.NewSession()
		if err != nil {
			log.Fatal("Failed to create session: ", err)
		}

		// Once a Session is created, you can execute a single command on
		// the remote side using the Run method.
		var b bytes.Buffer
		session.Stdout = &b
		if err := session.Run(command); err != nil {
			log.Fatal("Failed to run: " + err.Error())
		}
		out <- b.String()
		session.Close()
	}

	close(out)
}

func getPassword() (string, error) {
	fmt.Print("Enter private key Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	password := string(bytePassword)
	return password, nil
}

func decryptKey(key []byte) []byte {
	block, rest := pem.Decode(key)
	if len(rest) > 0 {
		log.Fatalf("Extra data included in key")
	}

	if x509.IsEncryptedPEMBlock(block) {
		password, err := getPassword()
		fmt.Println("")
		if err != nil {
			log.Fatalf("Failed to get key password: %v", err)
		}

		der, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	}
	return key
}
