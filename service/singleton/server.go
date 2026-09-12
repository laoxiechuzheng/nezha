package singleton

import (
	"cmp"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"

	"github.com/nezhahq/nezha/model"
	"github.com/nezhahq/nezha/pkg/utils"
)

type ServerClass struct {
	class[uint64, *model.Server]

	// lifecycleMu serializes changes to the authoritative server entries with
	// synchronous ServiceSentinel report processing.
	lifecycleMu sync.RWMutex

	geoIPReportLocks sync.Map
	ddnsDispatcher   *ddnsDispatcher

	uuidToID map[string]uint64

	sortedListForGuest []*model.Server
}

func NewServerClass() *ServerClass {
	sc := &ServerClass{
		class: class[uint64, *model.Server]{
			list: make(map[uint64]*model.Server),
		},
		uuidToID:       make(map[string]uint64),
		ddnsDispatcher: newDDNSDispatcher(defaultDDNSConcurrency, nil, nil),
	}

	var servers []model.Server
	DB.Find(&servers)
	for i := range servers {
		innerS := &servers[i]
		model.InitServer(innerS)
		sc.list[innerS.ID] = innerS
		sc.uuidToID[innerS.UUID] = innerS.ID
	}
	sc.sortList()

	model.OwnerServerIDsLookup = sc.ownerServerIDs
	model.AllServerIDsLookup = sc.allServerIDs
	model.OwnerIsAdminLookup = ownerIsAdmin

	return sc
}

func (c *ServerClass) lockLifecycleRead() {
	c.lifecycleMu.RLock()
}

func (c *ServerClass) unlockLifecycleRead() {
	c.lifecycleMu.RUnlock()
}

func (c *ServerClass) lockLifecycleWrite() {
	c.lifecycleMu.Lock()
}

func (c *ServerClass) unlockLifecycleWrite() {
	c.lifecycleMu.Unlock()
}

func (c *ServerClass) geoIPReportLock(serverID uint64) *sync.Mutex {
	lock, _ := c.geoIPReportLocks.LoadOrStore(serverID, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

func (c *ServerClass) AcceptGeoIPReport(serverID uint64, geoIP model.GeoIP) (*model.Server, model.GeoIP, bool, error) {
	c.lockLifecycleRead()
	defer c.unlockLifecycleRead()

	lock := c.geoIPReportLock(serverID)
	lock.Lock()
	defer lock.Unlock()

	server, ok := c.Get(serverID)
	if !ok || server == nil {
		return nil, model.GeoIP{}, false, fmt.Errorf("server not found")
	}

	var previous model.GeoIP
	if server.GeoIP != nil {
		previous = *server.GeoIP
	}
	changed := previous.IP.IPv4Addr != geoIP.IP.IPv4Addr
	server.GeoIP = &geoIP
	if changed && server.EnableDDNS && geoIP.IP.IPv4Addr != "" {
		if err := c.UpdateDDNS(server, &geoIP.IP); err != nil {
			log.Printf("NEZHA>> Failed to queue DDNS update for server %d: %v", server.ID, err)
		}
	}
	return server, previous, changed, nil
}

func (c *ServerClass) ownerServerIDs(ownerUID uint64) []uint64 {
	var ids []uint64
	c.Range(func(id uint64, s *model.Server) bool {
		if s != nil && s.GetUserID() == ownerUID {
			ids = append(ids, id)
		}
		return true
	})
	return ids
}

func (c *ServerClass) allServerIDs() []uint64 {
	var ids []uint64
	c.Range(func(id uint64, s *model.Server) bool {
		if s != nil {
			ids = append(ids, id)
		}
		return true
	})
	return ids
}

func ownerIsAdmin(ownerUID uint64) bool {
	return userIsAdmin(ownerUID)
}

func (c *ServerClass) Update(s *model.Server, uuid string) {
	c.lockLifecycleWrite()
	defer c.unlockLifecycleWrite()

	if c.ddnsDispatcher != nil {
		c.ddnsDispatcher.cancelServer(s.ID)
	}
	c.listMu.Lock()

	c.list[s.ID] = s
	if uuid != "" {
		c.uuidToID[uuid] = s.ID
	}

	c.listMu.Unlock()

	if s.EnableDDNS {
		if err := c.UpdateDDNS(s, nil); err != nil {
			log.Printf("NEZHA>> Failed to update DDNS for server %d: %v", s.ID, err)
		}
	}

	c.sortList()
}

func (c *ServerClass) Delete(idList []uint64) {
	c.lockLifecycleWrite()
	defer c.unlockLifecycleWrite()

	for _, id := range idList {
		if c.ddnsDispatcher != nil {
			c.ddnsDispatcher.cancelServer(id)
		}
		c.geoIPReportLocks.Delete(id)
	}
	c.listMu.Lock()

	for _, id := range idList {
		s, ok := c.list[id]
		if !ok {
			continue
		}
		delete(c.uuidToID, s.UUID)
		delete(c.list, id)
	}

	c.listMu.Unlock()

	c.sortList()
}

// setUserID updates in-memory ownership under the server lifecycle lock so a
// transfer cannot change authorization during synchronous report processing.
func (c *ServerClass) setUserID(id, userID uint64) {
	c.lockLifecycleWrite()
	defer c.unlockLifecycleWrite()

	if s, ok := c.Get(id); ok && s != nil {
		s.SetUserID(userID)
	}
}

func (c *ServerClass) GetSortedListForGuest() []*model.Server {
	c.sortedListMu.RLock()
	defer c.sortedListMu.RUnlock()

	return slices.Clone(c.sortedListForGuest)
}

func (c *ServerClass) UUIDToID(uuid string) (id uint64, ok bool) {
	c.listMu.RLock()
	defer c.listMu.RUnlock()

	id, ok = c.uuidToID[uuid]
	return
}

func (c *ServerClass) UpdateDDNS(server *model.Server, ip *model.IP) error {
	if c.ddnsDispatcher == nil {
		return fmt.Errorf("DDNS dispatcher is not initialized")
	}
	dnsServers := configuredDNSServers(Conf.DNSServers)
	selectedIP := ip
	if selectedIP == nil {
		if server.GeoIP == nil {
			return fmt.Errorf("server %d has no reported IP", server.ID)
		}
		selectedIP = &server.GeoIP.IP
	}
	if selectedIP.IPv4Addr == "" {
		return nil
	}

	providers, err := DDNSShared.GetDDNSProvidersFromProfiles(server.DDNSProfiles, selectedIP, server.GetUserID())
	if err != nil {
		return err
	}

	for _, provider := range providers {
		domains := server.OverrideDDNSDomains[provider.GetProfileID()]
		if len(domains) == 0 {
			domains = provider.DDNSProfile.Domains
		}
		for _, domain := range domains {
			taskProvider, err := DDNSShared.providerFromProfile(provider.DDNSProfile, &model.IP{
				IPv4Addr: provider.IPAddrs.IPv4Addr,
				IPv6Addr: provider.IPAddrs.IPv6Addr,
			})
			if err != nil {
				return err
			}
			c.ddnsDispatcher.enqueue(ddnsDispatchTask{
				serverID: server.ID, profileID: provider.GetProfileID(), domain: domain,
				provider: taskProvider, dnsServers: slices.Clone(dnsServers),
			})
		}
	}

	return nil
}

func configuredDNSServers(raw string) []string {
	servers := make([]string, 0)
	for _, server := range strings.Split(raw, ",") {
		if server = strings.TrimSpace(server); server != "" {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		return slices.Clone(utils.DNSServers)
	}
	return servers
}

func (c *ServerClass) sortList() {
	c.listMu.RLock()
	defer c.listMu.RUnlock()
	c.sortedListMu.Lock()
	defer c.sortedListMu.Unlock()

	c.sortedList = utils.MapValuesToSlice(c.list)
	// 按照服务器 ID 排序的具体实现（ID越大越靠前）
	slices.SortStableFunc(c.sortedList, func(a, b *model.Server) int {
		if a.DisplayIndex == b.DisplayIndex {
			return cmp.Compare(a.ID, b.ID)
		}
		return cmp.Compare(b.DisplayIndex, a.DisplayIndex)
	})

	c.sortedListForGuest = make([]*model.Server, 0, len(c.sortedList))
	for _, s := range c.sortedList {
		if !s.HideForGuest {
			c.sortedListForGuest = append(c.sortedListForGuest, s)
		}
	}
}
