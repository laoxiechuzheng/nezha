package singleton

import (
	"log"
	"time"

	"github.com/nezhahq/nezha/model"
)

const serviceHistoryCheckpointInterval = time.Minute

// persistServiceHistoryCheckpoint keeps a sparse SQLite safety copy while
// TSDB stores every probe. One real point per minute plus every state change
// is enough to preserve a useful timeline if a container is ever recreated
// with a missing TSDB mount, without returning to high-frequency SQLite growth.
func (ss *ServiceSentinel) persistServiceHistoryCheckpoint(serviceID, serverID uint64, at time.Time, delay float64, successful bool, message string) {
	if DB == nil {
		return
	}

	key := serviceHistoryCheckpointKey{serviceID: serviceID, serverID: serverID}
	ss.historyCheckpointLock.Lock()
	if ss.historyCheckpoints == nil {
		ss.historyCheckpoints = make(map[serviceHistoryCheckpointKey]serviceHistoryCheckpoint)
	}
	checkpoint, exists := ss.historyCheckpoints[key]
	shouldWrite := !exists ||
		checkpoint.successful != successful ||
		at.Sub(checkpoint.writtenAt) >= serviceHistoryCheckpointInterval
	ss.historyCheckpointLock.Unlock()
	if !shouldWrite {
		return
	}

	if len(message) > 512 {
		message = message[:512]
	}
	history := &model.ServiceHistory{
		ServiceID: serviceID,
		ServerID:  serverID,
		CreatedAt: at,
		AvgDelay:  delay,
		Data:      message,
	}
	if successful {
		history.Up = 1
	} else {
		history.Down = 1
	}
	if err := DB.Create(history).Error; err != nil {
		log.Printf("NEZHA>> Failed to save SQLite service history checkpoint: %v", err)
		return
	}

	ss.historyCheckpointLock.Lock()
	ss.historyCheckpoints[key] = serviceHistoryCheckpoint{writtenAt: at, successful: successful}
	ss.historyCheckpointLock.Unlock()
}
