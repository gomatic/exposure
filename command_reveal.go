package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/urfave/cli"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

//
func command_reveal(ctx *cli.Context) error {
	args := ctx.Args()

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(settings.Region),
	})
	if err != nil {
		return err
	}

	var file, keyid string
	var bin *bufio.Reader

	if len(args) < 1 {
		if isTTY() {
			log.Println("source: stdin")
		}
		bin = bufio.NewReader(os.Stdin)
		file = settings.FileKey
	} else {
		file = args[0]

		if strings.HasPrefix(file, "file://") {

			fi, err := os.Open(strings.TrimPrefix(file, "file://"))
			if err != nil {
				return err
			}
			defer fi.Close()
			bin = bufio.NewReader(fi)

		} else if strings.HasPrefix(file, "http://") {

			log.Println("TODO")

		} else {

			if strings.HasPrefix(file, "s3://") {
				uri, err := url.Parse(file)
				if err != nil {
					return err
				}
				settings.Bucket = uri.Host
				file = strings.TrimPrefix(uri.Path, "/")
			} else if settings.Bucket == "" {
				return errors.New("A bucket is required.")
			}

			s3params := &s3.GetObjectInput{
				Bucket:                     aws.String(settings.Bucket),
				Key:                        aws.String(file),
			}
			svcs3 := s3.New(sess)
			s3resp, err := svcs3.GetObject(s3params)

			if err != nil {
				return err
			}

			bin = bufio.NewReader(s3resp.Body)
		}
	}

	// version
	var (
		version      string
		major, minor string
	)

	version_re := regexp.MustCompile(`-----BEGIN SECRET/(\d+)[.](\d+)----`)
	for {
		v, err := bin.ReadString('\n')
		if err != nil {
			return err
		}
		if strings.HasPrefix(v, "-----BEGIN SECRET") && version_re.MatchString(v) {
			grouped := version_re.FindAllStringSubmatch(v, -1)
			if len(grouped) != 1 || len(grouped[0]) != 3 {
				return errors.New("Unexpected beginning")
			} else {
				major, minor = grouped[0][1], grouped[0][2]
				if _, err := strconv.ParseInt(grouped[0][1], 10, 64); err != nil {
					return errors.New(fmt.Sprintf("Invalid major version: %s", major))
				} else if _, err := strconv.ParseInt(grouped[0][2], 10, 64); err != nil {
					return errors.New(fmt.Sprintf("Invalid minor version: %s", minor))
				}
			}
			version = v[0: len(v) - 1]
			break
		}
	}

	if version == "" {
		return errors.New("Found no secret")
	}

	switch major {
	case "1":
		return v1(sess, bin, keyid, version, major, minor, file)
	}

	return errors.New(fmt.Sprintf("Version %s is not supported", major))
}

// TODO improve this signature
func v1(sess *session.Session, bin *bufio.Reader, keyid, version, major, minor, file string) error {
	// skip sourceKey
	bin.ReadString('\n')

	// mac
	cipherMAC64, err := bin.ReadString('\n')
	if err != nil {
		return err
	}
	cipherMAC64 = cipherMAC64[0: len(cipherMAC64) - 1]

	cipherMAC, err := base64.StdEncoding.DecodeString(string(cipherMAC64))
	if err != nil {
		return err
	}

	// wrapper
	wrapper64, err := bin.ReadString('\n')
	if err != nil {
		return err
	}
	wrapper64 = wrapper64[0: len(wrapper64) - 1]

	wrapper, err := base64.StdEncoding.DecodeString(string(wrapper64))
	if err != nil {
		return err
	}

	svckms := kms.New(sess)

	kmsparams := &kms.DecryptInput{
		CiphertextBlob: wrapper,
		EncryptionContext:   map[string]*string{
			"sourceKey":aws.String(path.Base(file)),
		},
	}
	if settings.Output.Verbose {
		log.Printf("%+v", kmsparams)
	}

	resp, err := svckms.Decrypt(kmsparams)

	if err != nil {
		return err
	}

	key := resp.Plaintext[:32]
	hmacKey := resp.Plaintext[32:]

	cipher64, err := bin.ReadBytes('\n')
	if err != nil {
		return err
	}
	cipher64 = cipher64[0: len(cipher64) - 1]

	ciphertext, err := base64.StdEncoding.DecodeString(string(cipher64))
	if err != nil {
		return err
	}

	end, err := bin.ReadString('\n')
	if err != nil {
		return err
	} else if end != fmt.Sprintf("-----END SECRET/%s.%s-----\n", major, minor) {
		log.Println("WARNING: Missing ending")
	}

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(version))
	mac.Write(key)
	mac.Write(hmacKey)
	mac.Write(wrapper)
	mac.Write(ciphertext)
	expectedMAC := mac.Sum(nil)

	if settings.Output.Debugging {
		log.Print("key:", key)
		log.Print("hmacKey:", hmacKey)
		log.Print("wrapper:", wrapper)
		log.Print("ciphertext:", ciphertext)
		log.Print("cipherMAC:", cipherMAC)
	}

	if !hmac.Equal(cipherMAC, expectedMAC) {
		return errors.New("Inauthentic")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	fmt.Print(string(plaintext))

	if settings.ssh.AuthSock != "" && file != "" {
		privkey, err := ssh.ParseRawPrivateKey(plaintext)
		if err != nil {
			return err
		}

		sshkey := agent.AddedKey{
			PrivateKey:   privkey,
			Comment:      file,
		}

		sock, err := net.Dial("unix", settings.ssh.AuthSock)
		if err != nil {
			return err
		}

		sshAgent := agent.NewClient(sock)

		if err := sshAgent.Add(sshkey); err != nil {
			return nil
		}
	}

	return nil
}
