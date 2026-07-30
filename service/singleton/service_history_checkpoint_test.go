package singleton

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/nezhahq/nezha/model"
)

func TestServiceHistoryCheckpointIsSparseAndKeepsTransitions(t *testing.T) {
	originalDB := DB
	var err error
	DB, err = gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, DB.AutoMigrate(model.ServiceHistory{}))
	t.Cleanup(func() { DB = originalDB })

	ss := &ServiceSentinel{historyCheckpoints: make(map[serviceHistoryCheckpointKey]serviceHistoryCheckpoint)}
	start := time.Date(2026, 7, 30, 9, 0, 0, 0, time.UTC)
	ss.persistServiceHistoryCheckpoint(1, 2, start, 40, true, "")
	ss.persistServiceHistoryCheckpoint(1, 2, start.Add(30*time.Second), 41, true, "")
	ss.persistServiceHistoryCheckpoint(1, 2, start.Add(40*time.Second), 0, false, "timeout")
	ss.persistServiceHistoryCheckpoint(1, 2, start.Add(50*time.Second), 42, true, "")
	ss.persistServiceHistoryCheckpoint(1, 2, start.Add(2*time.Minute), 43, true, "")

	var histories []model.ServiceHistory
	require.NoError(t, DB.Order("created_at").Find(&histories).Error)
	require.Len(t, histories, 4)
	require.Equal(t, []uint64{1, 0, 1, 1}, []uint64{histories[0].Up, histories[1].Up, histories[2].Up, histories[3].Up})
	require.Equal(t, uint64(1), histories[1].Down)
	require.Equal(t, "timeout", histories[1].Data)
}
