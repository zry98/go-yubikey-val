package database

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
	log "github.com/sirupsen/logrus"
	"go-yubikey-val/internal/config"
	"time"
)

type statements struct {
	GetClientData                  *sql.Stmt
	GetQueueLength                 *sql.Stmt
	GetQueueLengthByServer         *sql.Stmt
	GetYubiKey                     *sqlx.Stmt
	GetYubikeySecretKey            *sql.Stmt
	UpdateYubiKeyCounters          *sqlx.NamedStmt
	AddYubiKey                     *sqlx.NamedStmt
	ToggleYubiKey                  *sql.Stmt
	GetAllActiveYubiKeyPublicNames *sqlx.Stmt
	UpdateQueue                    *sqlx.Stmt
}

var (
	DB    *sqlx.DB
	stmts statements
)

func Setup() {
	var err error
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4",
		config.DB.Username, config.DB.Password, config.DB.Host, config.DB.Port, config.DB.Name)
	DB, err = sqlx.Connect("mysql", dsn)
	if err != nil {
		log.Fatal("Could not connect to database: ", err)
	}
	log.Infof("Connected to database: tcp(%s:%s)/%s",
		config.DB.Host, config.DB.Port, config.DB.Name)
	DB.SetMaxIdleConns(config.DB.MaxIdleConnections)
	DB.SetMaxOpenConns(config.DB.MaxOpenConnections)
}

func PrepareStatements() {
	var err error
	stmts.GetClientData, err = DB.Prepare(`SELECT id, secret FROM clients WHERE active=1 AND id=?`)
	checkError(err)
	stmts.GetQueueLength, err = DB.Prepare(`SELECT COUNT(*) FROM queue`)
	checkError(err)
	stmts.GetQueueLengthByServer, err = DB.Prepare(`SELECT server, COUNT(server) AS queue_length FROM queue GROUP BY server`)
	checkError(err)
	stmts.GetYubiKey, err = DB.Preparex(`SELECT * FROM yubikeys WHERE public_name=? LIMIT 1`)
	checkError(err)
	stmts.GetYubikeySecretKey, err = DB.Prepare(`SELECT secret_key FROM yubikeys WHERE public_name=? LIMIT 1`)
	checkError(err)
	stmts.UpdateYubiKeyCounters, err = DB.PrepareNamed(`UPDATE yubikeys SET modified_at=:modified_at, session_counter=:session_counter, use_counter=:use_counter, timestamp_low=:timestamp_low, timestamp_high=:timestamp_high, nonce=:nonce WHERE public_name=:public_name AND (session_counter<:session_counter OR (session_counter=:session_counter AND use_counter<:use_counter))`)
	checkError(err)
	stmts.AddYubiKey, err = DB.PrepareNamed(`INSERT INTO yubikeys VALUES (:public_name, :active, :created_at, :modified_at, :session_counter, :use_counter, :timestamp_low, :timestamp_high, :nonce, :notes, :secret_key)`)
	checkError(err)
	stmts.ToggleYubiKey, err = DB.Prepare(`UPDATE yubikeys SET active=? WHERE public_name=?`)
	checkError(err)
	stmts.GetAllActiveYubiKeyPublicNames, err = DB.Preparex(`SELECT public_name FROM yubikeys WHERE active=TRUE`)
	checkError(err)
	stmts.UpdateQueue, err = DB.Preparex(`UPDATE queue SET queued_at=NULL WHERE server_nonce=?`)
	checkError(err)
}

func CloseStatements() {
	_ = stmts.GetClientData.Close()
}

func GetClientData(clientId int32) (Client, error) {
	var client Client
	err := stmts.GetClientData.QueryRow(clientId).Scan(&client.Id, &client.Secret)

	return client, err
}

func GetLocalParams(publicName string) (Params, error) {
	log.Debug("searching for public name ", publicName, " in local db")
	var localParams Params
	err := stmts.GetYubiKey.QueryRowx(publicName).StructScan(&localParams.YubiKey)
	if err == nil {
		log.Info("yubikey found in db ", localParams.YubiKey)
		return localParams, nil
	}

	if err == sql.ErrNoRows {
		log.Info("Discovered new identity ", publicName)
		yubikey := YubiKey{
			Active:         true,
			CreatedAt:      int32(time.Now().Unix()),
			ModifiedAt:     -1,
			PublicName:     publicName,
			SessionCounter: -1,
			UseCounter:     -1,
			TimestampLow:   -1,
			TimestampHigh:  -1,
			Nonce:          "0000000000000000",
			Notes:          "",
		}

		_, err = stmts.AddYubiKey.Exec(yubikey)
		if err == nil {
			err = stmts.GetYubiKey.QueryRowx(publicName).StructScan(&localParams.YubiKey)
			if err == nil {
				return localParams, nil
			}

			if err == sql.ErrNoRows {
				log.Info("params for public name ", publicName, " not found in database")
			}
		}
	}

	log.Error(err)
	return localParams, err
}

func UpdateDbCounters(yubikey YubiKey) bool {
	res, err := stmts.UpdateYubiKeyCounters.Exec(yubikey)
	if err != nil {
		log.Error("failed to update internal DB with new counters")
		return false
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		log.Error("failed to update internal DB with new counters")
		return false
	}
	if rowsAffected == 0 {
		log.Info("database not updated", yubikey)
	}

	log.Info("updated database", yubikey)
	return true
}

func checkError(err error) {
	if err != nil {
		log.Error(err)
		panic(err)
	}
}

func GetSecretKey(publicName string) (string, error) {
	var secretKey string
	err := stmts.GetYubikeySecretKey.QueryRow(publicName).Scan(&secretKey)
	if err != nil {
		return secretKey, err
	}

	if secretKey == "" {
		return secretKey, fmt.Errorf("Got empty secret key for %s", publicName)
	}

	return secretKey, nil
}
