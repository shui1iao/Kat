package route

import (
	"hash/crc32"
	"strconv"
	"sync"
	"weak"
)

// Parsed data is shared between engines (configuration generations) while the
// file and the parse parameters are unchanged, so a reload neither re-parses
// a large rule set nor keeps one copy per retained generation. Entries are
// weak: the data is freed when no engine uses it any more.
type cacheEntry struct {
	key  string
	set  weak.Pointer[setData]
	geo  weak.Pointer[geoDB]
	asn  weak.Pointer[asnDB]
	site weak.Pointer[siteDB]
}

var parsedCache struct {
	sync.Mutex
	m map[string]cacheEntry
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// cacheKey identifies the content (length and CRC-32C) and parse parameters.
func cacheKey(s *source, b []byte) string {
	return s.kind + "|" + s.stamp + "|" + strconv.Itoa(len(b)) + "|" + strconv.FormatUint(uint64(crc32.Checksum(b, castagnoli)), 16)
}

func cacheGet(path, key string) any {
	parsedCache.Lock()
	defer parsedCache.Unlock()
	c, ok := parsedCache.m[path]
	if !ok || c.key != key {
		return nil
	}
	switch {
	case c.set.Value() != nil:
		return c.set.Value()
	case c.geo.Value() != nil:
		return c.geo.Value()
	case c.asn.Value() != nil:
		return c.asn.Value()
	case c.site.Value() != nil:
		return c.site.Value()
	}
	delete(parsedCache.m, path)
	return nil
}

func cachePut(path, key string, v any) {
	c := cacheEntry{key: key}
	switch x := v.(type) {
	case *setData:
		c.set = weak.Make(x)
	case *geoDB:
		c.geo = weak.Make(x)
	case *asnDB:
		c.asn = weak.Make(x)
	case *siteDB:
		c.site = weak.Make(x)
	default:
		return
	}
	parsedCache.Lock()
	if parsedCache.m == nil {
		parsedCache.m = map[string]cacheEntry{}
	}
	parsedCache.m[path] = c
	parsedCache.Unlock()
}
