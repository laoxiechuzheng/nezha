package singleton

import (
	"log"
	"time"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/tsdb"
)

var TSDBShared *tsdb.TSDB

func InitTSDB() error {
	config := &tsdb.Config{
		DataPath:           "data/tsdb",
		RetentionDays:      30,
		MinFreeDiskSpaceGB: 1,
		MaxMemoryMB:        256,
	}

	if Conf.TSDB.DataPath != "" {
		config.DataPath = Conf.TSDB.DataPath
	}
	if Conf.TSDB.RetentionDays > 0 {
		config.RetentionDays = Conf.TSDB.RetentionDays
	}
	if Conf.TSDB.MinFreeDiskSpaceGB > 0 {
		config.MinFreeDiskSpaceGB = Conf.TSDB.MinFreeDiskSpaceGB
	}
	if Conf.TSDB.MaxMemoryMB > 0 {
		config.MaxMemoryMB = Conf.TSDB.MaxMemoryMB
	}
	if Conf.TSDB.WriteBufferSize > 0 {
		config.WriteBufferSize = Conf.TSDB.WriteBufferSize
	}
	if Conf.TSDB.WriteBufferFlushInterval > 0 {
		config.WriteBufferFlushInterval = time.Duration(Conf.TSDB.WriteBufferFlushInterval) * time.Second
	}

	if DB != nil {
		if err := DB.AutoMigrate(model.ServiceHistory{}); err != nil {
			return err
		}
	}

	if !config.Enabled() {
		log.Println("NEZHA>> TSDB is disabled (tsdb.data_path not configured)")
		return nil
	}

	var err error
	TSDBShared, err = tsdb.Open(config)
	if err != nil {
		return err
	}

	log.Println("NEZHA>> TSDB initialized successfully")

	log.Println("NEZHA>> SQLite service history fallback enabled for restart-safe continuity")

	return nil
}

func TSDBEnabled() bool {
	return TSDBShared != nil && !TSDBShared.IsClosed()
}

func CloseTSDB() {
	if TSDBShared != nil {
		TSDBShared.Close()
	}
}
