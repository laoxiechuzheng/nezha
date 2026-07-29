package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nezhahq/nezha/model"
)

func TestMergeServiceInfosPreservesPreRestartHistory(t *testing.T) {
	legacy := &model.ServiceInfos{
		ServiceID: 1, ServerID: 7, ServiceName: "TCP",
		CreatedAt: []int64{1000, 2000}, AvgDelay: []float64{10, 20},
		PacketLoss: []float64{0, 100}, Status: []uint8{1, 0}, ErrorCode: []uint8{0, 1},
	}
	tsdb := &model.ServiceInfos{
		ServiceID: 1, ServerID: 7, ServiceName: "TCP",
		CreatedAt: []int64{2000, 3000}, AvgDelay: []float64{22, 30},
		PacketLoss: []float64{0, 0}, Status: []uint8{1, 1}, ErrorCode: []uint8{0, 0},
	}

	merged := mergeServiceInfos(legacy, tsdb)

	assert.Equal(t, []int64{1000, 2000, 3000}, merged.CreatedAt)
	assert.Equal(t, []float64{10, 22, 30}, merged.AvgDelay)
	assert.Equal(t, []uint8{1, 1, 1}, merged.Status)
}
