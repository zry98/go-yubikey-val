package cmd

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
	"os"
	"strconv"
	"strings"
	"time"
)

// generateCmd represents the Generate command
var generateCmd = &cobra.Command{
	Use:   "gen",
	Short: "Generate YubiKey secrets or API clients",
	Long:  ``,
}

// generateKeysCmd represents the Generate YubiKeys command (originally yhsm-generate-keys)
var generateKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Generate YubiKey secrets",
	Long:  `Generate secrets for YubiKeys using YubiHSM`,
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

// generateClientsCmd represents the Generate Clients command (originally ykval-gen-clients)
var generateClientsCmd = &cobra.Command{
	Use:   "clients [num_clients]",
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
	device        string
	outputDir     string
	count         int32
	publicIdChars int32
	keyHandles    []string
	startPublicId string
	randomNonce   bool
	urandom       bool
	email         string
	notes         string
	otp           string
)

func init() {
	generateKeysCmd.Flags().StringVarP(&device, "device", "D", "/dev/ttyACM0", "YubiHSM device")
	generateKeysCmd.Flags().StringVarP(&outputDir, "output-dir", "O", "/var/cache/yubikey-ksm/aeads", "Output directory (AEAD base dir)")
	generateKeysCmd.Flags().Int32VarP(&count, "count", "c", 1, "Number of secrets to generate")
	generateKeysCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose operation")
	generateKeysCmd.Flags().Int32Var(&publicIdChars, "public-id-chars", 12, "Number of chars in generated public ids")
	generateKeysCmd.Flags().StringArrayVar(&keyHandles, "key-handles", nil, "Key handles to encrypt the generated secrets with")
	generateKeysCmd.Flags().StringVar(&startPublicId, "start-public-id", "", "The first public id to generate AEAD for")
	generateKeysCmd.Flags().BoolVar(&randomNonce, "random-nonce", false, "Let the HSM generate nonce")
	_ = generateKeysCmd.MarkFlagRequired("key-handles")
	_ = generateKeysCmd.MarkFlagRequired("start-public-id")
	generateCmd.AddCommand(generateKeysCmd)

	generateClientsCmd.Flags().BoolVar(&urandom, "urandom", false, "use /dev/urandom instead of /dev/random as entropy source")
	generateClientsCmd.Flags().StringVar(&email, "email", "", "set the e-mail field of the created clients")
	generateClientsCmd.Flags().StringVar(&notes, "notes", "", "set the notes field of the created clients")
	generateClientsCmd.Flags().StringVar(&otp, "otp", "", "set the otp field of the created clients")
	generateCmd.AddCommand(generateClientsCmd)

	rootCmd.AddCommand(generateCmd)
}

func generateKeys() {
	logging.Setup("generate-keys")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	if fi, err := os.Stat(outputDir); err != nil || !fi.IsDir() {
		log.Errorf("Output directory '%s' does not exist.\n", outputDir)
		fmt.Printf("Output directory '%s' does not exist.\n", outputDir)
		os.Exit(1)
		return
	}

	if _, err := os.Stat(device); err != nil {
		log.Errorf("Device '%s' does not exist.\n", device)
		fmt.Printf("Device '%s' does not exist.\n", device)
		os.Exit(1)
		return
	}

	handles := make(map[int32]string)
	for _, val := range keyHandles {
		for _, keyHandle := range strings.Split(val, ",") {
			handles[keyHandleToInt32(keyHandle)] = keyHandle
		}
	}
}

func keyHandleToInt32(keyHandle string) int32 {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Could not parse key_handle '%s'\n", keyHandle)
			os.Exit(1)
		}
	}()

	n, err := strconv.ParseInt(keyHandle, 0, 32)
	if err == nil {
		return int32(n)
	}

	return int32(binary.LittleEndian.Uint32([]byte(keyHandle)))
}

func generateClients(numClients int) {
	logging.Setup("generate-clients")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	var nextId int32
	err := database.DB.QueryRow(`SELECT id FROM clients ORDER BY id DESC LIMIT 1`).Scan(&nextId)
	if err != nil && err != sql.ErrNoRows {
		log.Error(err)
		fmt.Println(err)
		return
	}

	stmtInsertClient, err := database.DB.PrepareNamed(`INSERT INTO clients VALUES (:id, :active, :created_at, :secret, :email, :notes, :otp)`)
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
			log.Error("Failed to insert new client with query ", client)
			fmt.Println(err)
			fmt.Println("Failed to insert new client with query", client)
			return
		}

		fmt.Printf("%d,%s\n", client.Id, client.Secret)
	}

	log.Info("Successfully inserted generated clients into database")
}
