package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/atotto/clipboard"

	"github.com/urfave/cli"
)

// @TODO add support for backup to a cloud
// @TODO add support for restore from a cloud

// Flags
var (
	passphrase string
	action     string
	file       string
	key        string
	insecure   bool
)

func main() {
	app()
}

/*
	Core action handler
*/

func generate() error {
	// checkFlags
	err := checkFlags()
	if err != nil {
		return err
	}

	// get values from existed one or create a new
	var s = new(storage)
	if fileExists() {
		content, err := fileRead()
		if err != nil {
			return err
		}
		decrypted := decrypt(content, passphrase)
		s.unmarshal(decrypted)
		if (s.Values[key] != meta{}) {
			fmt.Println("Overwrite existed entry? (yes)")
			var answer string
			fmt.Scanf("%s", &answer)
			if strings.ToLower(answer) != "yes" {
				return nil
			}
		}
	} else {
		s.Values = make(map[string]meta)
	}

	// generate new password
	newPW, err := generateRandomString(18)
	if err != nil {
		return err
	}

	// define meta for new entry
	m := meta{
		Key:       key,
		Password:  newPW,
		Timestamp: time.Now().String(),
	}

	// add new entry and marshall
	s.Values[key] = m
	marshalled, err := s.marshal()
	if err != nil {
		return err
	}

	// encrypt it
	encrypted := encrypt(marshalled, passphrase)

	// write to the file
	err = fileWrite(encrypted)
	if err != nil {
		return err
	}

	// copy to the clpboard
	if insecure {
		fmt.Println(newPW)
	}
	return clipboard.WriteAll(newPW)
}

func get() error {
	// checkFlags
	err := checkFlags()
	if err != nil {
		return err
	}
	var pw string

	var s = new(storage)
	if fileExists() {
		content, err := fileRead()
		if err != nil {
			return err
		}
		decrypted := decrypt(content, passphrase)
		s.unmarshal(decrypted)
		if (s.Values[key] != meta{}) {
			pw = s.Values[key].Password
			fmt.Printf("Last refresh at %s\n", s.Values[key].Timestamp)
		} else {
			return errors.New("There isn't entry with this key")
		}
	} else {
		return errors.New("There isn't secure file")
	}

	if insecure {
		fmt.Println(pw)
	}
	return clipboard.WriteAll(pw)
}

func list() error {
	// check flags

	var s = new(storage)
	if fileExists() {
		content, err := fileRead()
		if err != nil {
			return err
		}
		decrypted := decrypt(content, passphrase)
		s.unmarshal(decrypted)
		for _, value := range s.Values {
			fmt.Printf("Key: %s - last update: %s\n", value.Key, value.Timestamp)
		}
		return nil
	}

	return errors.New("There isn't secure file")
}

/*
	CLI utils
*/

func app() {
	app := cli.NewApp()

	flags := []cli.Flag{
		cli.StringFlag{
			Name:        "passphrase",
			Value:       "",
			Usage:       "passphrase",
			Destination: &passphrase,
		},
		cli.StringFlag{
			Name:        "file",
			Value:       "secure",
			Usage:       "file",
			EnvVar:      "PASS_FILE",
			Destination: &file,
		},
		cli.StringFlag{
			Name:        "key",
			Value:       "",
			Usage:       "key",
			Destination: &key,
		},
		cli.BoolFlag{
			Name:        "insecure",
			Usage:       "Write password to prompt",
			Destination: &insecure,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:  "generate",
			Usage: "Generate a new password and save to the key",
			Flags: flags,
			Action: func(c *cli.Context) error {
				return generate()
			},
		},
		{
			Name:  "get",
			Usage: "Get the password by key",
			Flags: flags,
			Action: func(c *cli.Context) error {
				return get()
			},
		},
		{
			Name:  "list",
			Usage: "List the key entries",
			Flags: flags,
			Action: func(c *cli.Context) error {
				return list()
			},
		},
		{
			Name:  "backup",
			Usage: "Do a backup and save it to Google Drive",
			//Flags
			Action: func(c *cli.Context) error {
				log.Fatal("Not supported yet")
				return nil
			},
		},
		{
			Name:  "restore",
			Usage: "Get the file from Google Drive and restore it to the specified location",
			//Flags
			Action: func(c *cli.Context) error {
				log.Fatal("Not supported yet")
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func checkFlags() error {
	if passphrase == "" {
		return errors.New("Empty passphrase not supported")
	}
	if file == "" {
		return errors.New("Empty file name not allowed (use PASS_FILE env var)")
	}
	if key == "" {
		return errors.New("Empty key not allowed")
	}

	return nil
}

/*
	Storage
*/

type storage struct {
	Values map[string]meta `json:"values"`
}

type meta struct {
	Key       string `json:"key"`
	Password  string `json:"password"`
	Timestamp string `json:"timestamp"`
}

func (s *storage) marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *storage) unmarshal(data []byte) error {
	return json.Unmarshal(data, s)
}

/*
	File handlers
*/

func fileRead() ([]byte, error) {
	return ioutil.ReadFile(file)
}

func fileWrite(data []byte) error {
	return ioutil.WriteFile(file, data, 0644)
}

func fileExists() bool {
	_, err := os.Stat(file)
	if !os.IsNotExist(err) {
		return true
	}
	return false
}

/*
	Password generation
*/

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

/*
	Encrypt/Decrypt mechanism
*/

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}
