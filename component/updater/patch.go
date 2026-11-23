package updater

import (
	"context"
	"sync"

	"github.com/metacubex/mihomo/log"
)

var (
	GeoUpdateHook func(geoType string, updating bool, skipped bool, updateErr error)
	// 作者 long：下载进度独立于开始/终态hook，避免一次分块读取被当成新的更新生命周期。
	GeoProgressHook func(geoType string, downloaded, total int64, attempt int)
)

func sendGeoUpdateStatus(geoType string, updating bool, skipped bool, updateErr error) {
	if GeoUpdateHook != nil {
		GeoUpdateHook(geoType, updating, skipped, updateErr)
	}
}

var (
	geoUpdateMutex  sync.Mutex
	geoUpdateCancel context.CancelFunc
)

func StopGeoUpdater() {
	geoUpdateMutex.Lock()
	defer geoUpdateMutex.Unlock()
	stopGeoUpdater()
}

func stopGeoUpdater() {
	if geoUpdateCancel == nil {
		return
	}
	geoUpdateCancel()
	geoUpdateCancel = nil
}

func RegisterGeoUpdaterWithCancel() {
	geoUpdateMutex.Lock()
	defer geoUpdateMutex.Unlock()

	stopGeoUpdater()

	if updateInterval <= 0 {
		log.Infoln("[GEO] Invalid update interval: %d", updateInterval)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	geoUpdateCancel = cancel
	registerGeoUpdater(ctx)
}
