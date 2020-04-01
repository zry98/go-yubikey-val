package cmd

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
)

// exportCmd represents the Export command
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export YubiKey Info or Client Info data from the yubikey-val server",
	Long: `Output comma separated values containing YubiKey Info or Client Info 
formatted data from the yubikey-val database. This data can later be imported 
using the ` + "`go-ykval import` command",
}

// exportKeysCmd represents the Export YubiKeys command
var exportKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Export YubiKey Info data from the yubikey-val server",
	Long: `Output comma separated values containing YubiKey Info formatted data from 
the yubikey-val database. This data can later be imported using 
the ` + "`go-ykval import keys` command",
	Run: func(cmd *cobra.Command, args []string) {
		exportYubiKeys()
	},
}

// exportClientsCmd represents the Export Clients command
var exportClientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Export Client Info data from the yubikey-val server",
	Long: `Output comma separated values containing Client Info formatted data from 
the yubikey-val database. This data can later be imported using 
the ` + "`go-ykval import clients` command",
	Run: func(cmd *cobra.Command, args []string) {
		exportClients()
	},
}

func init() {
	exportCmd.AddCommand(exportKeysCmd)
	exportCmd.AddCommand(exportClientsCmd)
	rootCmd.AddCommand(exportCmd)
}

func exportYubiKeys() {
	logging.Setup("export-yubikeys")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	rows, err := database.DB.Queryx(`SELECT active, created_at, modified_at, public_name, session_counter, use_counter, timestamp_low, timestamp_high, nonce, notes FROM yubikeys ORDER BY public_name`)
	if err != nil {
		log.Error(err)
		return
	}

	for rows.Next() {
		var key database.YubiKey
		err := rows.StructScan(&key)
		if err != nil {
			log.Error(err)
		}

		var active int8
		if key.Active {
			active = 1
		}
		fmt.Printf("%d,%d,%d,%s,%d,%d,%d,%d,%s,%s\n",
			active,
			key.CreatedAt,
			key.ModifiedAt,
			key.PublicName,
			key.SessionCounter,
			key.UseCounter,
			key.TimestampLow,
			key.TimestampHigh,
			key.Nonce,
			key.Notes,
		)
	}
}

func exportClients() {
	logging.Setup("export-clients")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	rows, err := database.DB.Queryx(`SELECT id, active, created_at, secret, email, notes, otp FROM clients ORDER BY id`)
	if err != nil {
		log.Error(err)
		return
	}

	for rows.Next() {
		var client database.Client
		err := rows.StructScan(&client)
		if err != nil {
			log.Error(err)
		}

		var active int8
		if client.Active {
			active = 1
		}
		fmt.Printf("%d,%d,%d,%s,%s,%s,%s\n",
			client.Id,
			active,
			client.CreatedAt,
			client.Secret,
			client.Email,
			client.Notes,
			client.Otp,
		)
	}
}
