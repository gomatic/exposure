package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/urfave/cli"
)

//
func getPlainSource(args []string) ([]byte, error) {
	var in io.Reader = os.Stdin
	if len(args) < 2 {
		if isTTY() {
			log.Println("source: stdin")
		}
	} else {
		fi, err := os.Open(args[1])
		if err != nil {
			return nil, err
		}
		defer fi.Close()
		in = fi
	}
	return ioutil.ReadAll(in)
}

//
func command_conceal(ctx *cli.Context) error {
	args := ctx.Args()

	var plaintext []byte
	if len(args) < 1 {
		return errors.New("Missing required parameters.")
	} else if settings.Value != "" {
		plaintext = []byte(settings.Value)
	} else {
		pt, err := getPlainSource(args)
		if err != nil {
			return err
		}
		plaintext = pt
	}

	keyid := args[0]

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(settings.Region),
	})
	if err != nil {
		return err
	}

	svckms := kms.New(sess)

	params := &kms.GenerateDataKeyInput{
		KeyId:               aws.String(keyid),
		NumberOfBytes:       aws.Int64(64),
	}
	resp, err := svckms.GenerateDataKey(params)

	if err != nil {
		return err
	}

	key := resp.Plaintext[:32]
	hmacKey := resp.Plaintext[32:]
	wrapper := resp.CiphertextBlob
	wrapper64 := base64.StdEncoding.EncodeToString(wrapper)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize + len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	version := fmt.Sprintf("-----BEGIN SECRET/%s-----", MAJOR)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(version))
	mac.Write(key)
	mac.Write(hmacKey)
	mac.Write(wrapper)
	mac.Write(ciphertext)
	cipherMAC := mac.Sum(nil)

	cipherMAC64 := base64.StdEncoding.EncodeToString(cipherMAC)
	cipher64 := base64.StdEncoding.EncodeToString(ciphertext)

	fmt.Println(version)
	fmt.Println(cipherMAC64)
	fmt.Println(wrapper64)
	fmt.Println(cipher64)
	fmt.Printf("-----END SECRET/%s-----\n", MAJOR)

	if settings.Output.Debugging {
		log.Print("key:", key)
		log.Print("hmacKey:", hmacKey)
		log.Print("wrapper:", wrapper)
		log.Print("ciphertext:", ciphertext)
		log.Print("cipherMAC:", cipherMAC)
	}

	return nil
}
