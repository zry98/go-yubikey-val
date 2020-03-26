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
	UpdateCounters                 *sqlx.NamedStmt
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

func GetClientData(clientId int32) (Client, error) {
	var client Client
	err := stmts.GetClientData.QueryRow(clientId).Scan(&client.Id, &client.Secret)
	if err != nil {
		log.Error(err)
	}

	return client, err
}

func GetLocalParams(publicName string) (Params, error) {
	log.Debug("searching for yk_publicname", publicName, "in local db")
	var localParams Params
	var err error
	err = stmts.GetYubiKey.QueryRowx(publicName).StructScan(&localParams.YubiKey)
	if err == nil {
		log.Info("yubikey found in db", localParams)
		return localParams, nil
	}

	if err == sql.ErrNoRows {
		log.Info("Discovered new identity", publicName)
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
				log.Info("params for yk_publicname", publicName, "not found in database")
			} else {
				log.Error(err)
			}
		}

	} else {
		log.Error(err)
	}

	return localParams, err
}

func UpdateDbCounters(yubikey YubiKey) bool {
	res, err := stmts.UpdateCounters.Exec(yubikey)
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

func PrepareStatements() {
	var err error
	stmts.GetClientData, err = DB.Prepare(`SELECT id, secret FROM clients WHERE active=1 AND id=?;`)
	checkError(err)
	stmts.GetQueueLength, err = DB.Prepare(`SELECT COUNT(*) FROM queue;`)
	checkError(err)
	stmts.GetQueueLengthByServer, err = DB.Prepare(`SELECT server, COUNT(server) AS queue_length FROM queue GROUP BY server;`)
	checkError(err)
	stmts.GetYubiKey, err = DB.Preparex(`SELECT * FROM yubikeys WHERE yk_publicname=? LIMIT 1;`)
	checkError(err)
	stmts.UpdateCounters, err = DB.PrepareNamed(`UPDATE yubikeys SET modified=:modified, yk_counter=:yk_counter, yk_use=:yk_use, yk_low=:yk_low, yk_high=:yk_high, nonce=:nonce WHERE yk_publicname=:yk_publicname AND (yk_counter<:yk_counter OR (yk_counter=:yk_counter AND yk_use<:yk_use));`)
	checkError(err)
	stmts.AddYubiKey, err = DB.PrepareNamed(`INSERT INTO yubikeys (active, created, modified, yk_publicname, yk_counter, yk_use, yk_low, yk_high, nonce, notes) VALUES (:active, :created, :modified, :yk_publicname, :yk_counter, :yk_use, :yk_low, :yk_high, :nonce, :notes);`)
	checkError(err)
	stmts.ToggleYubiKey, err = DB.Prepare(`UPDATE yubikeys SET active=? WHERE yk_publicname=?;`)
	checkError(err)
	stmts.GetAllActiveYubiKeyPublicNames, err = DB.Preparex(`SELECT yk_publicname FROM yubikeys WHERE active=TRUE;`)
	checkError(err)
	stmts.UpdateQueue, err = DB.Preparex(`UPDATE queue SET queued=NULL WHERE server_nonce=?;`)
	checkError(err)
}

func CloseStatements() {
	_ = stmts.GetClientData.Close()
}

func checkError(err error) {
	if err != nil {
		log.Error(err)
		panic(err)
	}
}
