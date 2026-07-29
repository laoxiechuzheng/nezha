package singleton

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
)

func TestInitTSDBPreservesLegacyServiceHistory(t *testing.T) {
	var err error
	DB, err = gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, DB.AutoMigrate(model.ServiceHistory{}))
	require.NoError(t, DB.Create(&model.ServiceHistory{ServiceID: 1, ServerID: 2, AvgDelay: 10, Up: 1}).Error)

	originalConf := Conf
	Conf = &ConfigClass{}
	Conf.TSDB.DataPath = filepath.Join(t.TempDir(), "tsdb")
	t.Cleanup(func() {
		CloseTSDB()
		TSDBShared = nil
		DB = nil
		Conf = originalConf
	})

	require.NoError(t, InitTSDB())
	require.True(t, DB.Migrator().HasTable(&model.ServiceHistory{}))
	var count int64
	require.NoError(t, DB.Model(&model.ServiceHistory{}).Count(&count).Error)
	require.Equal(t, int64(1), count)
}
