package geoip

import (
	_ "embed"
	"errors"
	"net"
	"strings"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

//go:embed geoip.db
var db []byte

var (
	dbOnce = sync.OnceValues(func() (*maxminddb.Reader, error) {
		db, err := maxminddb.FromBytes(db)
		if err != nil {
			return nil, err
		}
		return db, nil
	})
)

func Lookup(ip net.IP) (string, error) {
	db, err := dbOnce()
	if err != nil {
		return "", err
	}

	var record map[string]any
	err = db.Lookup(ip, &record)
	if err != nil {
		return "", err
	}

	if code := lookupCountryCode(record); code != "" {
		return strings.ToLower(code), nil
	}

	return "", errors.New("IP not found")
}

func lookupCountryCode(record map[string]any) string {
	if country, ok := record["country"].(string); ok && strings.TrimSpace(country) != "" {
		return country
	}
	if country, ok := record["country"].(map[string]any); ok {
		if code, ok := country["iso_code"].(string); ok && strings.TrimSpace(code) != "" {
			return code
		}
	}
	if continent, ok := record["continent"].(string); ok && strings.TrimSpace(continent) != "" {
		return continent
	}
	if continent, ok := record["continent"].(map[string]any); ok {
		if code, ok := continent["code"].(string); ok && strings.TrimSpace(code) != "" {
			return code
		}
	}
	return ""
}
