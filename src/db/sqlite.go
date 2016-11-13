package db

import (
	"database/sql"
	"fmt"
	"github.com/mattn/go-sqlite3"
)

type TestItem struct {
	DstIP             string
	SrcIP             string
	Compromised       string
	TimeClassifiedUTC string
	Description       string
	Action            string
	Success           string
	PacketID          string
}

func CreateTable(db *sql.DB) {
	// create table if not exists

	fmt.Println("CREATING TABLE")
	sql_table := `
	CREATE TABLE IF NOT EXISTS packets(
		DstIP TEXT,
		SrcIP TEXT,
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

// Drops packets table if it exists.
func DropTable(db *sql.DB) {
	stmt := `DROP TABLE IF EXISTS packets;`
	_, err := db.Exec(stmt)
	if err != nil {
		panic(err)
	}
}

func StoreItem(db *sql.DB, item TestItem) error {
	fmt.Println("item.PacketID", item.PacketID)

	sql_additem := `
	INSERT OR REPLACE INTO packets(
		DstIP,
		SrcIP,
		Compromised,
		TimeClassifiedUTC,
		Description,
		Action,
		Success,
		PacketID
	) values(?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := db.Prepare(sql_additem)
	if err != nil {
		panic(err)
	}
	defer stmt.Close()

	_, err2 := stmt.Exec(item.DstIP, item.SrcIP, item.Compromised, item.TimeClassifiedUTC, item.Description, item.Action, item.Success, item.PacketID)
	if err2 != nil {
		panic(err2)
	}

	return nil
}

func ReadItem(db *sql.DB) []TestItem {
	sql_readall := `
	SELECT DstIP, SrcIP, Compromised, TimeClassifiedUTC, Description, Action, Success, PacketID FROM packets
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
		err2 := rows.Scan(&item.DstIP, &item.SrcIP, &item.Compromised, &item.TimeClassifiedUTC, &item.Description, &item.Action, &item.Success, &item.PacketID)
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
