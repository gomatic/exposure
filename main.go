package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
)

//
const MAJOR = "1.0"

var VERSION = "1"

//
type application struct {
	Bucket  string
	Region  string
	FileKey string
	// The positional parameter is key name for this provided value
	Value string
	ssh struct {
		// SSH_AUTH_SOCK
		AuthSock string
		Add      bool
	}
	Output struct {
		Debugging bool
		Verbose   bool
	}
}

//
var settings application

//
func main() {
	app := cli.NewApp()
	app.Name = "exposure"
	app.Usage = "Conceal or reveal data using AWS KMS keys."
	app.Version = MAJOR + "." + VERSION
	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "region, r",
			Value:       "us-east-1",
			EnvVar:      "AWS_REGION",
			Destination: &settings.Region,
		},
		cli.StringFlag{
			Name:        "key, k",
			Usage:       "If the input is stdin, provide the key the data represents.",
			Value:       "",
			Destination: &settings.FileKey,
		},
		cli.BoolFlag{
			Name:        "verbose, V",
			Destination: &settings.Output.Verbose,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:      "conceal",
			Aliases:   []string{"c"},
			Usage:     "Conceal data.",
			ArgsUsage: "key-name [data]",
			Action:    command_conceal,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "value, v",
					Destination: &settings.Value,
				},
			},
			After: verbose,
		},
		{
			Name:      "reveal",
			Aliases:   []string{"r"},
			Usage:     "Reveal data.",
			ArgsUsage: "[secret]",
			Action:    command_reveal,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "bucket, b",
					Value:       "",
					EnvVar:      "CONCEALED_BUCKET",
					Destination: &settings.Bucket,
				},
				//// TODO This requires a lot more work
				//cli.BoolFlag{
				//	Name:        "ssh",
				//	Destination: &settings.ssh.Add,
				//},
			},
			Before: func(ctx *cli.Context) error {
				if settings.ssh.Add {
					if sock, exists := os.LookupEnv("SSH_AUTH_SOCK"); !exists || sock == "" {
						log.Print("WARNING: Requested SSH but SSH_AUTH_SOCK does not exist.")
					} else {
						settings.ssh.AuthSock = sock
					}
				}
				return nil
			},
			After: verbose,
		},
	}
	app.Run(os.Args)
}

//
func verbose(ctx *cli.Context) error {
	log.Printf("%+v", settings)
	return nil
}
