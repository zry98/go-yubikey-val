package cmd

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
	"strconv"
	"time"
)

// generateCmd represents the gen command (originally ykval-gen-clients)
var generateCmd = &cobra.Command{
	Use:   "gen [num_clients]",
	Short: "Generate Yubikey API clients",
	Long: `Generate clients and client secrets, and insert them into the yubikey-val
database. They are also printed to stdout as comma separated lines 
containing client_id, secret`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		if len(args) == 1 {
			_, err := strconv.Atoi(args[0])
			if err != nil && err.(*strconv.NumError).Err == strconv.ErrSyntax {
				return fmt.Errorf("num_clients should be an integer\n")
			}
			return err
		}
		return fmt.Errorf("invalid number of args\n")
	},
	Run: func(cmd *cobra.Command, args []string) {
		numClients := 1
		if len(args) == 1 {
			numClients, _ = strconv.Atoi(args[0])
		}
		generateClients(numClients)
	},
}

var (
	urandom bool
	email   string
	notes   string
	otp     string
)

func init() {
	generateCmd.Flags().BoolVar(&urandom, "urandom", false, "use /dev/urandom instead of /dev/random as entropy source")
	generateCmd.Flags().StringVar(&email, "email", "", "set the e-mail field of the created clients")
	generateCmd.Flags().StringVar(&notes, "notes", "", "set the notes field of the created clients")
	generateCmd.Flags().StringVar(&otp, "otp", "", "set the otp field of the created clients")
	rootCmd.AddCommand(generateCmd)
}

func generateClients(numClients int) {
	logging.Setup("generate-clients")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	var nextId int32
	err := database.DB.QueryRow(`SELECT id FROM clients ORDER BY id DESC LIMIT 1;`).Scan(&nextId)
	if err != nil && err != sql.ErrNoRows {
		log.Error(err)
		fmt.Println(err)
		return
	}

	stmtInsertClient, err := database.DB.PrepareNamed(`INSERT INTO clients (id, active, created, secret, email, notes, otp) VALUES (:id, :active, :created, :secret, :email, :notes, :otp);`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	for i := 0; i < numClients; i++ {
		nextId++
		// generate random bytes for the client secret
		b := make([]byte, 20)
		_, err := rand.Read(b)
		if err != nil {
			log.Error(err)
			fmt.Println(err)
			return
		}

		client := database.Client{
			Id:        nextId,
			Active:    true,
			CreatedAt: int32(time.Now().Unix()),
			Secret:    base64.StdEncoding.EncodeToString(b),
			Email:     email,
			Notes:     notes,
			Otp:       otp,
		}
		_, err = stmtInsertClient.Exec(client)
		if err != nil {
			log.Error(err)
			log.Error("Failed to insert new client with query", client)
			fmt.Println(err)
			fmt.Println("Failed to insert new client with query", client)
			return
		}

		fmt.Printf("%d,%s\n", client.Id, client.Secret)
	}

	log.Info("Successfully inserted generated clients into database")
}
