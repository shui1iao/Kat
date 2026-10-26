package kernel

import "github.com/shui1iao/Kat/internal/route"

// CheckRouteFiles parses the local rule set, GeoIP, geosite and ASN files of
// a validated configuration (kat check). Unsupported rule types or options,
// invalid content and exceeded limits are errors; missing files are not.
func (c *Config) CheckRouteFiles() error {
	if len(c.route.RuleSets) == 0 && c.route.GeoIP == nil && c.route.Geosite == nil && c.route.ASN == nil {
		return nil
	}
	return route.CheckFiles(c.route)
}
