package db

import (
	"database/sql"
	"fmt"
	"github.com/mattn/go-sqlite3"
)

type TestItem struct {
	MAC               string
	Compromised       string
	TimeClassifiedUTC string
	Description       string
	Action            string
	Success           string
	PacketID          string
}

func CreateTable(db *sql.DB) {
	// create table if not exists
	sql_table := `
	CREATE TABLE IF NOT EXISTS packets(
		MAC TEXT,
		Compromised TEXT,
		TimeClassifiedUTC TEXT,
		Description TEXT,
		Action TEXT,
		Success TEXT,
		PacketID TEXT NOT NULL PRIMARY KEY
	);
	`

	_, err := db.Exec(sql_table)
	if err != nil {
		panic(err)
	}
}

func DropTable(db *sql.DB) {
	stmt := `DROP TABLE packets;`
	_, err := db.Exec(stmt)
	if err != nil {
		panic(err)
	}
}

func StoreItem(db *sql.DB, item TestItem) error {
	fmt.Println("item.PacketID", item.PacketID)

	sql_additem := `
	INSERT OR REPLACE INTO packets(
		MAC,
		Compromised,
		TimeClassifiedUTC,
		Description,
		Action,
		Success,
		PacketID
	) values(?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	_, err2 := stmt.Exec(item.MAC, item.Compromised, item.TimeClassifiedUTC, item.Description, item.Action, item.Success, item.PacketID)
	if err2 != nil {
		panic(err2)
	}

	return nil
}

func ReadItem(db *sql.DB) []TestItem {
	sql_readall := `
	SELECT MAC, Compromised, TimeClassifiedUTC, Description, Action, Success, PacketID FROM packets
	ORDER BY PacketID DESC
	`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var result []TestItem
	for rows.Next() {
		item := TestItem{}
		err2 := rows.Scan(&item.MAC, &item.Compromised, &item.TimeClassifiedUTC, &item.Description, &item.Action, &item.Success, &item.PacketID)
		if err2 != nil {
			panic(err2)
		}
		result = append(result, item)
	}
	return result
}

// Register database driver.
func CreateAndRegisterDriver() string {
	var DB_DRIVER string
	sql.Register(DB_DRIVER, &sqlite3.SQLiteDriver{})
	return DB_DRIVER
}
