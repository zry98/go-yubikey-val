package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
	"go-yubikey-val/internal/utils"
	"os"
	"strconv"
)

// importCmd represents the Import command
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import Yubikey Info or Client Info data into the yubikey-val server",
	Long: `Read yubikey-val YubiKey Info or Client Info data from stdin 
and import it into the yubikey-val servers database. The data should 
previously have been exported using the ` + "`go-ykval export` command",
}

// importKeysCmd represents the Import YubiKeys command (originally ykval-import)
var importKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Import Yubikey Info data into the yubikey-val server",
	Long: `Read yubikey-val Yubikey Info data from stdin and import it into the 
yubikey-val servers database. The data should previously have been exported 
using the ` + "`go-ykval export keys` command",
	Run: func(cmd *cobra.Command, args []string) {
		importYubiKeys()
	},
}

// importClientsCmd represents the Import Clients command (originally ykval-import-clients)
var importClientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Import Client Info data into the yubikey-val server",
	Long: `Read yubikey-val Client Info data from stdin and import it into the 
yubikey-val servers database. The data should previously have been exported 
using ` + "`go-ykval export clients` command",
	Run: func(cmd *cobra.Command, args []string) {
		importClients()
	},
}

func init() {
	importCmd.AddCommand(importKeysCmd)
	importCmd.AddCommand(importClientsCmd)
	rootCmd.AddCommand(importCmd)
}

func importYubiKeys() {
	logging.Setup("import-yubikeys")
	defer logging.File.Close()

	lines, err := utils.Fgetcsv(os.Stdin, 0, ',')
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	database.Setup()
	defer database.DB.Close()

	stmtCheckKeyExists, err := database.DB.Preparex(`SELECT EXISTS (SELECT 1 FROM yubikeys WHERE yk_publicname=?);`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}
	stmtInsertKey, err := database.DB.PrepareNamed(`INSERT INTO yubikeys (active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes) VALUES (:active, :created, :modified, :yk_publicname, :yk_counter, :yk_use, :yk_low, :yk_high, :nonce, :notes);`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}
	stmtUpdateKey, err := database.DB.PrepareNamed(`UPDATE yubikeys SET active=:active, created=:created, modified=:modified, yk_counter=:yk_counter, yk_use=:yk_use, yk_high=:yk_low, nonce=:nonce, notes=:notes WHERE yk_publicname=:yk_publicname AND (yk_counter<:yk_counter OR (yk_counter=:yk_counter AND yk_use<:yk_use));`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	for _, line := range lines {
		key := database.YubiKey{
			Active:         true,
			CreatedAt:      mustToInt32(line[1]),
			ModifiedAt:     mustToInt32(line[2]),
			PublicName:     line[3],
			SessionCounter: mustToInt32(line[4]),
			UseCounter:     mustToInt32(line[5]),
			TimestampLow:   mustToInt32(line[6]),
			TimestampHigh:  mustToInt32(line[7]),
			Nonce:          line[8],
			Notes:          line[9],
		}
		if line[0] == "0" {
			key.Active = false
		}

		var keyExists bool
		err := stmtCheckKeyExists.Get(&keyExists, key.PublicName)
		if err != nil {
			log.Error(err)
			log.Error("Failed to check existence of YubiKey with query", key)
			fmt.Println(err)
			fmt.Println("Failed to check existence of YubiKey with query", key)
			return
		}

		if keyExists {
			_, err := stmtUpdateKey.Exec(key)
			if err != nil {
				log.Error(err)
				log.Error("Failed to update YubiKey with query", key)
				fmt.Println(err)
				fmt.Println("Failed to update YubiKey with query", key)
				return
			}
		} else {
			_, err := stmtInsertKey.Exec(key)
			if err != nil {
				log.Error(err)
				log.Error("Failed to insert new YubiKey with query", key)
				fmt.Println(err)
				fmt.Println("Failed to insert new YubiKey with query", key)
				return
			}
		}
	}

	log.Info("Successfully imported yubikeys to database")
	fmt.Println("Successfully imported yubikeys to database")
}

func importClients() {
	logging.Setup("import-clients")
	defer logging.File.Close()

	lines, err := utils.Fgetcsv(os.Stdin, 0, ',')
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	database.Setup()
	defer database.DB.Close()

	stmtCheckClientExists, err := database.DB.Preparex(`SELECT EXISTS (SELECT 1 FROM clients WHERE id=?);`)
	if err != nil {
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

	for _, line := range lines {
		client := database.Client{
			Id:        mustToInt32(line[0]),
			Active:    true,
			CreatedAt: mustToInt32(line[2]),
			Secret:    line[3],
			Email:     line[4],
			Notes:     line[5],
			Otp:       line[6],
		}
		if line[1] == "0" {
			client.Active = false
		}

		var clientExists bool
		err := stmtCheckClientExists.Get(&clientExists, client.Id)
		if err != nil {
			log.Error(err)
			log.Error("Failed to check existence of client with query", client)
			fmt.Println(err)
			fmt.Println("Failed to check existence of client with query", client)
			return
		}

		if clientExists == false {
			_, err := stmtInsertClient.Exec(client)
			if err != nil {
				log.Error(err)
				log.Error("Failed to insert new client with query", client)
				fmt.Println(err)
				fmt.Println("Failed to insert new client with query", client)
				return
			}
		}
	}

	log.Info("Successfully imported clients to database")
	fmt.Println("Successfully imported clients to database")
}

func mustToInt32(str string) int32 {
	integer, err := strconv.Atoi(str)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		os.Exit(1)
	}
	return int32(integer)
}
