package mmdb

import (
	"github.com/metacubex/mihomo/component/preflight"
	"sync"

	mihomoOnce "github.com/metacubex/mihomo/common/once"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/oschwald/maxminddb-golang"
)

type databaseType = uint8

const (
	typeMaxmind databaseType = iota
	typeSing
	typeMetaV0
)

var (
	ipReader  IPReader
	asnReader ASNReader
	ipOnce    sync.Once
	asnOnce   sync.Once
)

func LoadFromBytes(buffer []byte) {
	ipOnce.Do(func() {
		mmdb, err := maxminddb.FromBytes(buffer)
		if err != nil {
			log.Fatalln("Can't load mmdb: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
}

func Verify(path string) bool {
	instance, err := maxminddb.Open(path)
	if err == nil {
		instance.Close()
	}
	return err == nil
}

func IPInstance() IPReader {
	ipOnce.Do(func() {
		mmdbPath := C.Path.MMDB()
		log.Infoln("Load MMDB file: %s", mmdbPath)
		mmdb, err := maxminddb.Open(mmdbPath)
		if err != nil {
			log.Fatalln("Can't load MMDB: %s", err.Error())
		}
		ipReader = IPReader{Reader: mmdb}
		switch mmdb.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})

	return ipReader
}

func ASNInstance() ASNReader {
	asnOnce.Do(func() {
		ASNPath := C.Path.ASN()
		log.Infoln("Load ASN file: %s", ASNPath)
		asn, err := maxminddb.Open(ASNPath)
		if err != nil {
			log.Fatalln("Can't load ASN: %s", err.Error())
		}
		asnReader = ASNReader{Reader: asn}
	})

	return asnReader
}

func ReloadIP() {
	mihomoOnce.Reset(&ipOnce)
}

func ReloadASN() {
	mihomoOnce.Reset(&asnOnce)
}

// 作者 long：预检的坏Geo数据必须返回错误，不Fatal退出或访问磁盘；只允许一次性隔离解析上下文调用。
func LoadValidationBytes(buffer []byte, asn bool) error {
	if !preflight.Enabled() {
		return preflight.ErrReadOnly
	}
	reader, err := maxminddb.FromBytes(buffer)
	if err != nil {
		return err
	}
	if asn {
		asnOnce.Do(func() { asnReader = ASNReader{Reader: reader} })
		if asnReader.Reader != reader {
			reader.Close()
		}
		return nil
	}
	ipOnce.Do(func() {
		ipReader = IPReader{Reader: reader}
		switch reader.Metadata.DatabaseType {
		case "sing-geoip":
			ipReader.databaseType = typeSing
		case "Meta-geoip0":
			ipReader.databaseType = typeMetaV0
		default:
			ipReader.databaseType = typeMaxmind
		}
	})
	if ipReader.Reader != reader {
		reader.Close()
	}
	return nil
}
