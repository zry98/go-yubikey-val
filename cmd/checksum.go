package cmd

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go-yubikey-val/internal/database"
	"go-yubikey-val/internal/logging"
)

// checksumCmd represents the Checksum command
var checksumCmd = &cobra.Command{
	Use:   "checksum",
	Short: "Calculate a checksum of all deactivated YubiKeys Info or Client Info data",
	Long: `Calculate a checksum of the state of all deactivated YubiKey Info or 
Client Info data in the yubikey-val server database. This checksum can be used 
to easily compare the state of disabled YubiKeys in two yubikey-val servers 
in the same sync pool.`,
}

// checksumDeactivatedKeysCmd represents the Checksum Deactivated YubiKeys command (originally ykval-checksum-deactivated)
var checksumDeactivatedKeysCmd = &cobra.Command{
	Use:   "deactivated",
	Short: "Calculate a checksum of all deactivated YubiKeys Info data",
	Long: `Calculate a checksum of the state of all deactivated YubiKey Info data 
in the yubikey-val server database. This checksum can be used to easily compare 
the state of disabled YubiKeys in two yubikey-val servers in the same sync pool.`,
	Run: func(cmd *cobra.Command, args []string) {
		checksumDeactivatedKeys()
	},
}

// checksumClientsCmd represents the Checksum Clients command (originally ykval-checksum-clients)
var checksumClientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Calculate a checksum of all Client Info data",
	Long: `Calculate a checksum using the id, active, and secret fields of all Client 
Info data in the yubikey-val server database. This checksum can be used to 
easily compare the state of clients in two yubikey-val servers in the same 
sync pool`,
	Run: func(cmd *cobra.Command, args []string) {
		checksumClients()
	},
}

var (
	verbose bool
)

func init() {
	checksumCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "make the operation more talkative")
	checksumCmd.AddCommand(checksumDeactivatedKeysCmd)
	checksumCmd.AddCommand(checksumClientsCmd)
	rootCmd.AddCommand(checksumCmd)
}

func checksumDeactivatedKeys() {
	logging.Setup("checksum-deactivated-yubikeys")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	rows, err := database.DB.Queryx(`SELECT public_name, session_counter, use_counter FROM yubikeys WHERE active=FALSE ORDER BY public_name`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	var everything string
	for rows.Next() {
		var key database.YubiKey
		err := rows.StructScan(&key)
		if err != nil {
			log.Error(err)
			fmt.Println(err)
			return
		}
		everything += fmt.Sprintf("%s\t%d\t%d\n",
			key.PublicName, key.SessionCounter, key.UseCounter)
	}

	if verbose {
		fmt.Print(everything)
	}

	h := sha1.New()
	h.Write([]byte(everything))
	hash := hex.EncodeToString(h.Sum(nil))

	fmt.Println(hash[0:10])
}

func checksumClients() {
	logging.Setup("checksum-clients")
	defer logging.File.Close()

	database.Setup()
	defer database.DB.Close()

	rows, err := database.DB.Queryx(`SELECT id, active, secret FROM clients ORDER BY id`)
	if err != nil {
		log.Error(err)
		fmt.Println(err)
		return
	}

	var everything string
	for rows.Next() {
		var client database.Client
		err := rows.StructScan(&client)
		if err != nil {
			log.Error(err)
			fmt.Println(err)
			return
		}
		var active int32
		if client.Active {
			active = 1
		}
		everything += fmt.Sprintf("%d\t%d\t%s\n",
			client.Id, active, client.Secret)
	}

	if verbose {
		fmt.Print(everything)
	}

	h := sha1.New()
	h.Write([]byte(everything))
	hash := hex.EncodeToString(h.Sum(nil))

	fmt.Println(hash[0:10])
}
