package store

import (
	"strings"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func New(dsn string) (*gorm.DB, error) {

	if !strings.Contains(dsn, "_foreign_keys=") {
		if !strings.Contains(dsn, "?") {
			dsn += "?_foreign_keys=on"
		} else if strings.HasSuffix(dsn, "?") || strings.HasSuffix(dsn, "&") {
			dsn += "_foreign_keys=on"
		} else {
			dsn += "&_foreign_keys=on"
		}
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, err
	}

	err = db.AutoMigrate(
		&Network{},
		&Host{},
		&HostPort{},
		&Service{},
		&ServicePort{},
		&ServiceDependency{},
		&Website{},
		&PasswordEntry{},
		&Inject{},
		&Assignee{},
		&File{},
		&AllowedIP{},
	)
	if err != nil {
		return nil, err
	}

	var ipCount int64
	db.Model(&AllowedIP{}).Count(&ipCount)
	if ipCount == 0 {
		db.Create(&AllowedIP{CIDR: "127.0.0.1/32", Description: "Localhost IPv4"})
		db.Create(&AllowedIP{CIDR: "::1/128", Description: "Localhost IPv6"})
	}

	return db, nil
}
