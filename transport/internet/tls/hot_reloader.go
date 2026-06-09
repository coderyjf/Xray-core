package tls

import (
	"context"
	"crypto/tls"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/ocsp"
	"github.com/xtls/xray-core/common/platform/filesystem"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/common/uuid"
)

var (
	certsCache       = utils.NewWeakCacheMap[[16]byte, Certificate]()
	parsedCertsCache = utils.NewWeakCacheMap[[16]byte, tls.Certificate]()
	globalProtoLock  sync.RWMutex
)

var statHotreload sync.Once

func setupHotReload(entry *Certificate) {
	statHotreload.Do(func() {
		go handleHotReload()
	})
	uid := uuid.New()
	entry.Id = uid[:]
	if entry.OneTimeLoading {
		return
	}
	certsCache.Store(uid, entry)
}

func handleHotReload() {
	// should be enough?
	t := time.NewTicker(600 * time.Second)
	for {
		<-t.C
		certsCache.Range(
			func(_ [16]byte, entry *Certificate) bool {
				var reloaded bool
				defer func(c *Certificate) {
					if reloaded {
						// delete the old parsed cert to update
						parsedCertsCache.Delete([16]byte(c.Id))
					}
				}(entry)
				reloadIntervarl := int64(entry.OcspStapling)
				if reloadIntervarl <= 0 {
					reloadIntervarl = 3600
				}
				if entry.LastReload+reloadIntervarl >= time.Now().Unix() {
					return true
				} else {
					entry.LastReload = time.Now().Unix()
				}
				if entry.CertificatePath != "" && entry.KeyPath != "" {
					newCert, err := filesystem.ReadCert(entry.CertificatePath)
					if err != nil {
						errors.LogErrorInner(context.Background(), err, "failed to parse certificate")
						return true
					}
					newKey, err := filesystem.ReadCert(entry.KeyPath)
					if err != nil {
						errors.LogErrorInner(context.Background(), err, "failed to parse key")
						return true
					}
					if string(newCert) != string(entry.Certificate) || string(newKey) != string(entry.Key) {
						globalProtoLock.Lock()
						entry.Certificate = newCert
						entry.Key = newKey
						globalProtoLock.Unlock()
						reloaded = true
					}
				}
				if entry.OcspStapling > 0 {
					if newOCSPData, err := ocsp.GetOCSPForCert(entry.getX509KeyPair().Certificate); err != nil {
						errors.LogWarningInner(context.Background(), err, "ignoring invalid OCSP")
					} else if !slices.Equal(newOCSPData, entry.OcspData) {
						globalProtoLock.Lock()
						entry.OcspData = newOCSPData
						globalProtoLock.Unlock()
						reloaded = true
					}
				}
				return true
			})
	}
}
