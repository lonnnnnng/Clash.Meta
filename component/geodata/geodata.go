package geodata

import (
	"fmt"
	"github.com/metacubex/mihomo/component/preflight"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
)

type loader struct {
	LoaderImplementation
}

func (l *loader) LoadGeoSite(list string) ([]*router.Domain, error) {
	return l.LoadSiteByPath(C.GeositeName, list)
}

func (l *loader) LoadGeoIP(country string) ([]*router.CIDR, error) {
	return l.LoadIPByPath(C.GeoipName, country)
}

var loaders map[string]func() LoaderImplementation

func RegisterGeoDataLoaderImplementationCreator(name string, loader func() LoaderImplementation) {
	if loaders == nil {
		loaders = map[string]func() LoaderImplementation{}
	}
	loaders[name] = loader
}

func getGeoDataLoaderImplementation(name string) (LoaderImplementation, error) {
	if geoLoader, ok := loaders[name]; ok {
		return geoLoader(), nil
	}
	return nil, fmt.Errorf("unable to locate GeoData loader %s", name)
}

func GetGeoDataLoader(name string) (Loader, error) {
	loadImpl, err := getGeoDataLoaderImplementation(name)
	if err == nil && preflight.Enabled() {
		// 作者 long：保留原loader名称校验，内存校验采用同protobuf内容解析，避免文件路径与缓存写入。
		standard, standardErr := getGeoDataLoaderImplementation("standard")
		if standardErr != nil {
			return nil, standardErr
		}
		loadImpl = validationLoader{standard}
	}
	if err == nil {
		return &loader{loadImpl}, nil
	}
	return nil, err
}

// 作者 long：只读授权资源，保留真实国家/域名列表查找，不用空Geo数据放过错误引用。
type validationLoader struct{ LoaderImplementation }

func (v validationLoader) LoadSiteByPath(_ string, list string) ([]*router.Domain, error) {
	b, err := preflight.Resource("GEOSITE.dat")
	if err != nil {
		return nil, err
	}
	return v.LoadSiteByBytes(b, list)
}
func (v validationLoader) LoadIPByPath(_ string, country string) ([]*router.CIDR, error) {
	b, err := preflight.Resource("GEOIP.dat")
	if err != nil {
		return nil, err
	}
	return v.LoadIPByBytes(b, country)
}
