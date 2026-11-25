package ingest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
)

// Nodes keeps node_netinfo: each node's host network, read from the
// panel's node list (nodes:read) and the network information, with the
// admin's overrides left where they are (node identity is the addon's
// job).
type Nodes struct {
	DB    *gorm.DB
	Panel func() Getter
	Net   *netinfo.DB
	// CityFile is the city database on disk, scanned for the nodes'
	// cities (nodes are abroad, outside the kept table); "" for none.
	CityFile func() string
	// Resolve looks a node's host name up; nil is the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	Now     func() time.Time
}

type panelNode struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	LinkAddress string `json:"linkAddress"`
}

// Refresh reads the panel's nodes and writes what each one's address is.
func (n *Nodes) Refresh(ctx context.Context) error {
	if n.Panel == nil || n.Panel() == nil {
		return nil
	}
	// Every page: a node past the first one would otherwise have no network
	// here and lose its row — and the admin's correction with it — below.
	var list struct {
		Items []panelNode `json:"items"`
	}
	for offset := 0; ; offset += nodesPage {
		var page struct {
			Items []panelNode `json:"items"`
		}
		if err := n.Panel().Get(ctx, fmt.Sprintf("/nodes?limit=%d&offset=%d", nodesPage, offset), &page); err != nil {
			return err
		}
		list.Items = append(list.Items, page.Items...)
		if len(page.Items) < nodesPage || offset > 100*nodesPage {
			break
		}
	}
	addrs := map[uint]netip.Addr{}
	var scan []netip.Addr
	for _, node := range list.Items {
		if a, ok := n.addressOf(ctx, node); ok {
			addrs[node.ID] = a
			scan = append(scan, a)
		}
	}
	cities := map[netip.Addr]netinfo.Info{}
	if n.CityFile != nil {
		if path := n.CityFile(); path != "" {
			if got, err := netinfo.ScanCity(path, scan); err == nil {
				cities = got
			}
		}
	}
	now := time.Now
	if n.Now != nil {
		now = n.Now
	}
	return n.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		seen := make([]uint, 0, len(list.Items))
		for _, node := range list.Items {
			seen = append(seen, node.ID)
			row := model.NodeNetinfo{NodeID: node.ID}
			err := tx.First(&row, node.ID).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			row.Name = node.Name
			row.UpdatedAt = now().Unix()
			if a, ok := addrs[node.ID]; ok {
				info := n.Net.Lookup(a)
				row.Address, row.ASN, row.Org, row.Country = a.String(), info.ASN, info.Org, info.Country
				if c, ok := cities[a]; ok {
					row.Region, row.City = c.Region, c.City
					if row.Country == "" {
						row.Country = c.Country
					}
				}
			}
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
		}
		// A node deleted on the panel leaves; its history stays in the path
		// tables until retention takes it.
		q := tx.Where("1 = 1")
		if len(seen) > 0 {
			q = tx.Where("node_id NOT IN ?", seen)
		}
		return q.Delete(&model.NodeNetinfo{}).Error
	})
}

// addressOf is the address a node's clients dial: the first link address,
// else the control address, a host name resolved.
func (n *Nodes) addressOf(ctx context.Context, node panelNode) (netip.Addr, bool) {
	host := node.Address
	if first, _, _ := strings.Cut(node.LinkAddress, ","); strings.TrimSpace(first) != "" {
		if _, addr, found := strings.Cut(first, "|"); found {
			first = addr
		}
		host = first
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), true
	}
	if host == "" {
		return netip.Addr{}, false
	}
	resolve := n.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	got, err := resolve(rctx, host)
	if err != nil || len(got) == 0 {
		return netip.Addr{}, false
	}
	return got[0].Unmap(), true
}

// What the admin has to correct in an override.
var (
	ErrCountry  = errors.New("country must be a two-letter code")
	ErrOverride = errors.New("the provider or the city is too long")
)

const (
	// OverrideMax is the most characters a provider or city takes.
	OverrideMax = 64
	nodesPage   = 500
)

// Override sets what the admin says a node's network is; empty fields and
// a zero ASN put the database's answer back.
func Override(db *gorm.DB, nodeID uint, asn uint32, org, country, city string) error {
	country = strings.ToUpper(strings.TrimSpace(country))
	org, city = strings.TrimSpace(org), strings.TrimSpace(city)
	if country != "" && (len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z') {
		return ErrCountry
	}
	if utf8.RuneCountInString(org) > OverrideMax || utf8.RuneCountInString(city) > OverrideMax {
		return ErrOverride
	}
	res := db.Model(&model.NodeNetinfo{}).Where("node_id = ?", nodeID).Updates(map[string]any{
		"override_asn": asn, "override_org": org,
		"override_country": country, "override_city": city,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
