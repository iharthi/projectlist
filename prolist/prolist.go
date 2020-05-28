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
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"syscall"
	"gopkg.in/yaml.v2"
)

type DockerComposeHostEntry struct {
	Ports []string `yaml:"ports"`
	Volumes []string `yaml:"volumes"`
}

type DockerCompose struct {
	Services map[string]DockerComposeHostEntry `yaml:"services"`
}

func main() {
	keyPathPtr := flag.String("key", "", "SSH key path")
	serverNamePtr := flag.String("host", "", "Hostname to check")
	serverPortPrt := flag.Int("port", 22, "Port ssh runs on")
	usernamePtr := flag.String("user", "", "Username to use")
	useHttpPtr := flag.Bool("insecure", false, "Use HTTP instead of HTTPS")

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

	serverAddrList, err := net.LookupHost(*serverNamePtr)
	if err != nil {
		log.Fatalf("Couldn't resolve host %s: %v", *serverNamePtr, err)
		return
	}

	protocol := "https"
	if *useHttpPtr {
		protocol = "http"
	}

	sshConfig := createSshConfig(username, keyPath)

	commands := make(chan string, 10)
	results := make(chan string, 10)

	go runSshCommands(sshConfig, fmt.Sprintf("%s:%d", *serverNamePtr, *serverPortPrt), commands, results)

	commands <- "ls /etc/nginx/sites-enabled/"
	listString := <-results
	list := strings.Fields(listString)
	projects := make([]string, 0, len(list))

	// Filter the list
	for _, project := range list {
		if project == "default" {
			continue
		}
		projects = append(projects, project)
	}
	sort.Strings(projects)

	for _, project := range projects {
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

		if strings.HasPrefix(serverName, "www.") {
			serverName = serverName[4:]
		}

		dnsInfo := ""

		projectAddrList, err := net.LookupHost(serverName)
		if err != nil {
			dnsInfo = fmt.Sprintf(" [DNS issue: %v]", err)
		} else {
			if !checkAddrsMatch(serverAddrList, projectAddrList) {
				dnsInfo = " [DNS points to different host]"
			}
		}

		resp, err := http.Get(fmt.Sprintf("%s://%s/", protocol, serverName))
		if err != nil {
			fmt.Printf("[%s] %s: %s -> ERROR %v%s\n", *serverNamePtr, project, serverName, err, dnsInfo)
		} else {
			fmt.Printf("[%s] %s: %s -> %d%s\n", *serverNamePtr, project, serverName, resp.StatusCode, dnsInfo)
		}
	}

	// Now check for the exposed ports
	commands <- "ls -d /srv/*/docker-compose.production.yml"
	listStringSrv := <-results
	listSrv := strings.Fields(listStringSrv)
	projectsSrv := make([]string, 0, len(listSrv))

	// Filter the list
	for _, project := range listSrv {
		if project == "default" {
			continue
		}
		projectsSrv = append(projectsSrv, project)
	}
	sort.Strings(projectsSrv)

	for _, project := range projectsSrv {
		commands <- fmt.Sprintf("cat %s", project)
		result := <-results

		var m DockerCompose
		err := yaml.Unmarshal([]byte(result), &m)
		if err != nil {
			fmt.Printf("[%s] ERROR reading %s %v\n", *serverNamePtr, project, err)
		} else {
			for serviceName, service := range m.Services {
				if len(service.Ports) > 0 {
					fmt.Printf("[%s] %s:%s %s\n", *serverNamePtr, project, serviceName, service.Ports)
				}
			}
		}
	}

	close(commands)

	fmt.Println("All configured nginx projects in alphabetical order:")
	fmt.Println(strings.Join(projects, ", "))
}

func checkAddrsMatch(serverAddrList []string, projectAddrList []string) bool {
	for _, addr := range projectAddrList {
		found := false
		for _, serverAddr := range serverAddrList {
			if serverAddr == addr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
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
			log.Fatalf("Failed to run %s: %v", command, err)
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
