package rpc

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/nezhahq/nezha/model"
	geoipx "github.com/nezhahq/nezha/pkg/geoip"
	pb "github.com/nezhahq/nezha/proto"
	"github.com/nezhahq/nezha/service/singleton"
)

func (s *NezhaHandler) ReportGeoIP(ctx context.Context, report *pb.GeoIP) (*pb.GeoIP, error) {
	clientID, err := s.Auth.Check(ctx)
	if err != nil {
		return nil, err
	}
	geoIP := model.PB2GeoIP(report)
	if geoIP.IP.IPv4Addr == "" && geoIP.IP.IPv6Addr == "" {
		ip, _ := ctx.Value(model.CtxKeyRealIP{}).(string)
		if ip == "" {
			ip, _ = ctx.Value(model.CtxKeyConnectingIP{}).(string)
		}
		geoIP.IP.IPv4Addr = ip
	}
	joinedIP := geoIP.IP.Join()
	ip := geoIP.IP.IPv4Addr
	if geoIP.IP.IPv6Addr != "" && (report.GetUse6() || ip == "") {
		ip = geoIP.IP.IPv6Addr
	}
	location, err := geoipx.Lookup(net.ParseIP(ip))
	if err != nil {
		log.Printf("NEZHA>> geoip.Lookup: %v", err)
	}
	geoIP.CountryCode = location
	server, previousGeoIP, changed, err := singleton.ServerShared.AcceptGeoIPReport(clientID, geoIP)
	if err != nil {
		return nil, err
	}
	previousIP := previousGeoIP.IP.IPv4Addr
	if changed && singleton.Conf.EnableIPChangeNotification &&
		((singleton.Conf.Cover == model.ConfigCoverAll && !singleton.Conf.IgnoredIPNotificationServerIDs[clientID]) ||
			(singleton.Conf.Cover == model.ConfigCoverIgnoreAll && singleton.Conf.IgnoredIPNotificationServerIDs[clientID])) &&
		previousIP != "" && joinedIP != "" {
		singleton.NotificationShared.SendNotification(singleton.Conf.IPChangeNotificationGroupID,
			fmt.Sprintf("[%s] %s, %s => %s", singleton.Localizer.T("IP Changed"), server.Name,
				singleton.IPDesensitize(previousIP), singleton.IPDesensitize(joinedIP)), "")
	}
	return &pb.GeoIP{Ip: nil, CountryCode: location, DashboardBootTime: singleton.DashboardBootTime}, nil
}
