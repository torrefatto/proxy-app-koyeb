package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/rs/zerolog"
	"github.com/urfave/cli/v2"
)

var (
	basicAuthRe = regexp.MustCompile(`^[Bb]asic (.*)$`)
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app := &cli.App{
		Name:   "koyeb-proxy-app",
		Usage:  "A simple HTTP(S) proxy to be deployed on Koyeb",
		Action: run,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "debug",
				Aliases: []string{"d"},
				EnvVars: []string{"DEBUG"},
				Value:   false,
				Usage:   "Enable debug logs",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				EnvVars: []string{"VERBOSE"},
				Value:   false,
				Usage:   "Enable verbose logging from the proxy library",
			},
			&cli.UintFlag{
				Name:    "port",
				EnvVars: []string{"PORT"},
				Value:   8080,
				Usage:   "Port to listen on",
				Action: func(c *cli.Context, v uint) error {
					if v < 1 || v > 65535 {
						return cli.Exit("Port must be between 1 and 65535", 1)
					}
					return nil
				},
			},
			&cli.StringFlag{
				Name:    "user",
				EnvVars: []string{"USER"},
				Value:   "koyeb",
				Usage:   "User used to authenticate requests",
			},
			&cli.StringFlag{
				Name:     "secret",
				EnvVars:  []string{"SECRET"},
				Required: true,
				Usage:    "Secret used to authenticate requests",
			},
		},
	}

	logger := initLogger(ctx)

	ctx = logger.WithContext(ctx)

	if err := app.RunContext(ctx, os.Args); err != nil {
		logger.Fatal().Err(err).Msg("Failed to run app")
	}
	logger.Info().Msg("App stopped")
}

func initLogger(ctx context.Context) *zerolog.Logger {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	logger = logger.Level(zerolog.InfoLevel)
	return &logger
}

func run(c *cli.Context) error {
	logger := zerolog.Ctx(c.Context)

	if c.Bool("debug") {
		*logger = logger.Level(zerolog.DebugLevel)
	}

	c.Context = logger.WithContext(c.Context)

	logger.Debug().Msg("Debug level set")

	user := c.String("user")
	secret := c.String("secret")
	port := c.Uint("port")

	logger.Debug().Str("user", user).Msg("Configured credentials")

	proxy := goproxy.NewProxyHttpServer()
	if c.Bool("verbose") {
		proxy.Verbose = true
	}
	proxy.Logger = logger

	proxy.OnRequest().HijackConnect(func(r *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		u, p, ok := getProxyAuth(r, logger)
		logger := logger.With().Str("user", u).Logger()
		logger.Info().Str("url", r.URL.String()).Msg("Request received")
		if !ok || u != user || p != secret {
			logger.Debug().Str("user", u).Str("pass", p).Msg("Unauthorized request")
			client.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			client.Close()
			return
		}

		logger.Info().Str("url", r.URL.String()).Msg("Request authorized")

		remote, err := net.Dial("tcp", r.URL.Host)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to dial remote")
			client.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
			client.Close()
			return
		}

		client.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n"))

		go transfer(remote, client)
		go transfer(client, remote)
	})

	logger.Info().Uint("port", port).Msg("Starting proxy")

	return http.ListenAndServe(fmt.Sprintf(":%d", port), proxy)
}

func getProxyAuth(r *http.Request, logger *zerolog.Logger) (user string, password string, ok bool) {
	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		logger.Debug().Msg("No authorization header")
		return
	}

	parts := basicAuthRe.FindAllStringSubmatch(header, -1)
	if len(parts) != 1 || len(parts[0]) != 2 {
		logger.Debug().Str("Proxy-Authorization", header).Interface("parts", parts).Msg("Malformed header")
		return
	}

	creds, err := base64.StdEncoding.DecodeString(parts[0][1])
	if err != nil {
		logger.Debug().Err(err).Str("Proxy-Authorization", header).Msg("Malformed header")
		return
	}

	credsParts := strings.Split(string(creds), ":")
	if len(credsParts) != 2 {
		logger.Debug().Str("creds", string(creds)).Msg("Malformed credentials")
		return
	}

	return credsParts[0], credsParts[1], true
}

func transfer(dest io.WriteCloser, src io.ReadCloser) {
	defer func() { _ = dest.Close() }()
	defer func() { _ = src.Close() }()
	_, _ = io.Copy(dest, src)
}
