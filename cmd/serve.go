package cmd

import (
	"fmt"
	fasthttprouter "github.com/fasthttp/router"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/valyala/fasthttp"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
	"go-yubikey-val/internal/services/validation"
	"os"
	"os/signal"
	"syscall"
)

// serveCmd represents the Serve Validation Server command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a OTP Validation Server",
	Long: `Start a YubiKey OTP Validation Server listening on specified host and port. 
It's implemented follow the Validation Protocol Version 2.0 
(https://developers.yubico.com/yubikey-val/Validation_Protocol_V2.0.html), 
and it doesn't accept requests of protocol version lower than 2.0.
Syncing and other features are still under development.`,
	Run: func(cmd *cobra.Command, args []string) {
		serve()
	},
}

var (
	host string
	port int32
)

func init() {
	serveCmd.Flags().StringVar(&host, "host", "127.0.0.1",
		"set the host which the server should listen on")
	serveCmd.Flags().Int32Var(&port, "port", 8080,
		"set the port which the server should listen on")
	// TODO: verbose flag
	rootCmd.AddCommand(serveCmd)
}

func serve() {
	logging.Setup("server")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()
	database.PrepareStatements()
	defer database.CloseStatements()

	router := fasthttprouter.New()
	router.GET("/wsapi/2.0/verify", validation.Verify) // OTP Validation route

	server := fasthttp.Server{
		Handler: router.Handler,
	}

	listenAddress := fmt.Sprintf("%s:%d", host, port)

	go func() {
		if err := server.ListenAndServe(listenAddress); err != nil {
			log.Fatal(err)
		}
	}()
	log.Info("Server started, listening on ", listenAddress)
	fmt.Println("Server started, listening on", listenAddress)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Server shutdown")

	if err := server.Shutdown(); err != nil {
		log.Fatal("Server shutdown failed: ", err)
	}
}
