// Package model is Insight's own database (decision 28 in the panel's
// docs/product.md: an addon keeps its own). Nothing here holds a client
// address or prefix: a prefix exists only in memory between a poll and its
// ASN lookup (nx-panel docs/path-telemetry.md §4.4, exit criterion 1).
package model

import (
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// PathCounters are the additive counters of one cell. Medians do not add,
// so durations and RTTs are kept as weighted sums the readers divide.
type PathCounters struct {
	Accepted   uint64 `json:"accepted"`
	Authed     uint64 `json:"authed"`
	EarlyClose uint64 `json:"earlyClose"`

	FailedTLS     uint64 `json:"failedTls"`
	FailedAuth    uint64 `json:"failedAuth"`
	FailedTimeout uint64 `json:"failedTimeout"`
	FailedReset   uint64 `json:"failedReset"`
	FailedEOF     uint64 `json:"failedEof" gorm:"column:failed_eof"`
	FailedOther   uint64 `json:"failedOther"`
	FailedNoRoute uint64 `json:"failedNoRoute"`
	// FailedQUIC is datagrams to a plain QUIC inbound on a port set that no
	// QUIC client sends (quic_initial_bad); not connections, so not part of
	// any ratio over Accepted.
	FailedQUIC uint64 `json:"failedQuic" gorm:"column:failed_quic"`

	// Probe signals (nx-panel docs/path-telemetry.md §4.5): handshakes the
	// node saw before, and failures soon after another network's success.
	Replayed     uint64 `json:"replayed"`
	FollowUpFail uint64 `json:"followUpFail"`

	// DurSum is the sum of each sample's median session seconds times its
	// authenticated count, DurN that count; RTTSum/RTTN the same for the
	// median RTT in milliseconds; RetransSum/RetransN for the retransmit
	// rate in parts per million.
	DurSum     uint64 `json:"durSum"`
	DurN       uint64 `json:"durN"`
	RTTSum     uint64 `json:"rttSum" gorm:"column:rtt_sum"`
	RTTN       uint64 `json:"rttN" gorm:"column:rtt_n"`
	RetransSum uint64 `json:"retransSum"`
	RetransN   uint64 `json:"retransN"`

	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// PathCell names one cell: when, which node and inbound, which client
// network. ClientASN 0 is every ASN past the busiest ones of that node and
// inbound in that bucket (top-K folding); Country is the client's, Region
// its province or oblast as far as the city database can tell (an estimate:
// mobile carriers geolocate to their capital).
type PathCell struct {
	NodeID     uint   `json:"nodeId" gorm:"not null"`
	Inbound    string `json:"inbound" gorm:"not null;size:128"`
	ClientASN  uint32 `json:"clientAsn" gorm:"column:client_asn;not null"`
	Country    string `json:"country" gorm:"not null;size:2"`
	Region     string `json:"region" gorm:"not null;size:96"`
	Network    string `json:"network" gorm:"not null;size:4"`
	SourceKind string `json:"sourceKind" gorm:"not null;size:16"`
}

// PathHour is one cell over one hour, kept PathHourDays days.
type PathHour struct {
	ID uint `json:"id" gorm:"primaryKey"`
	// Hour is the unix second the hour starts at.
	Hour int64 `json:"hour" gorm:"not null"`
	PathCell
	PathCounters
}

func (PathHour) TableName() string { return "path_hours" }

// PathDay is one cell over one day (UTC), kept PathDayDays days.
type PathDay struct {
	ID  uint  `json:"id" gorm:"primaryKey"`
	Day int64 `json:"day" gorm:"not null"`
	PathCell
	PathCounters
}

func (PathDay) TableName() string { return "path_days" }

// TunnelCell names one tunnel link's hour on one node (nx-panel
// docs/path-telemetry.md P26): the tunnel's tag, the peer node's name, the
// address dialled (empty on the accepting side) and the side. A peer is
// one of the operator's own nodes, never a client.
type TunnelCell struct {
	Hour   int64  `json:"hour" gorm:"primaryKey;autoIncrement:false"`
	NodeID uint   `json:"nodeId" gorm:"primaryKey;autoIncrement:false"`
	Tunnel string `json:"tunnel" gorm:"primaryKey;size:128"`
	Peer   string `json:"peer" gorm:"primaryKey;size:128"`
	Server string `json:"server" gorm:"primaryKey;size:255"`
	Side   string `json:"side" gorm:"primaryKey;size:8"`
}

// TunnelCounters are a tunnel link's additive counts: attempts, links up,
// failures by step, links that came up and died before settling, and the
// links' lifetimes as a sum of each drain's median and how many there were.
type TunnelCounters struct {
	Attempts      uint64 `json:"attempts"`
	Up            uint64 `json:"up"`
	Flapped       uint64 `json:"flapped"`
	FailedDial    uint64 `json:"failedDial"`
	FailedTLS     uint64 `json:"failedTls" gorm:"column:failed_tls"`
	FailedPreface uint64 `json:"failedPreface"`
	FailedRefused uint64 `json:"failedRefused"`
	FailedTimeout uint64 `json:"failedTimeout"`
	FailedReset   uint64 `json:"failedReset"`
	FailedEOF     uint64 `json:"failedEof" gorm:"column:failed_eof"`
	FailedOther   uint64 `json:"failedOther"`
	LifetimeSum   uint64 `json:"lifetimeSum"`
	LifetimeN     uint64 `json:"lifetimeN"`
}

// Failed is every failure of the counters.
func (c TunnelCounters) Failed() uint64 {
	return c.FailedDial + c.FailedTLS + c.FailedPreface + c.FailedRefused + c.FailedTimeout + c.FailedReset + c.FailedEOF + c.FailedOther
}

// TunnelHour is one tunnel link over one hour, kept TunnelHourDays days.
type TunnelHour struct {
	TunnelCell
	TunnelCounters
}

func (TunnelHour) TableName() string { return "tunnel_hours" }

// TunnelHourDays is how long a tunnel hour is kept: a fleet has a handful
// of links, so they are not folded into days.
const TunnelHourDays = 30

// NodeNetinfo is what a node's address is: its host network, read from
// the network information, and what the admin set over it.
type NodeNetinfo struct {
	NodeID  uint   `json:"nodeId" gorm:"primaryKey;autoIncrement:false"`
	Name    string `json:"name"`
	Address string `json:"address"` // the IP looked up
	ASN     uint32 `json:"asn" gorm:"column:asn"`
	Org     string `json:"org"`
	Country string `json:"country" gorm:"size:2"`
	Region  string `json:"region"`
	City    string `json:"city"`
	// The overrides: a hosting provider whose ranges the database places
	// wrong, or an address behind a front. Empty or zero is "use the
	// database".
	OverrideASN     uint32 `json:"overrideAsn" gorm:"column:override_asn"`
	OverrideOrg     string `json:"overrideOrg"`
	OverrideCountry string `json:"overrideCountry" gorm:"size:2"`
	OverrideCity    string `json:"overrideCity"`
	UpdatedAt       int64  `json:"updatedAt"`
}

func (NodeNetinfo) TableName() string { return "node_netinfo" }

// Effective is the node's network with the overrides applied.
func (n NodeNetinfo) Effective() (asn uint32, org, country, city string) {
	asn, org, country, city = n.ASN, n.Org, n.Country, n.City
	if n.OverrideASN != 0 {
		asn = n.OverrideASN
	}
	if n.OverrideOrg != "" {
		org = n.OverrideOrg
	}
	if n.OverrideCountry != "" {
		country = n.OverrideCountry
	}
	if n.OverrideCity != "" {
		city = n.OverrideCity
	}
	return
}

// State is a small key-value row: the poll cursor, what the panel said
// about telemetry, the network information's freshness.
type State struct {
	Key   string `gorm:"primaryKey;size:64"`
	Value string
}

func (State) TableName() string { return "state" }

// PutState writes one state row, replacing the value it had.
func PutState(tx *gorm.DB, key, value string) error {
	return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.AssignmentColumns([]string{"value"})}).
		Create(&State{Key: key, Value: value}).Error
}

// OtherASN is the client ASN of everything without one of its own: prefixes
// no network announces, and the networks past the top-K an hour keeps
// (internal/ingest). It is a different mix every hour, so it is no network
// to judge, order links for, or tell a model about.
const OtherASN uint32 = 0

// Admin is one of Insight's own admins (the panel's are not Insight's).
type Admin struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	Username     string `json:"username" gorm:"uniqueIndex;not null"`
	PasswordHash string `json:"-" gorm:"not null"`
	// TOTPSecret is empty while the second factor is off; TOTPLastUsed is
	// the last time step accepted, so a code is never taken twice.
	TOTPSecret   string `json:"-" gorm:"not null;default:''"`
	TOTPLastUsed int64  `json:"-" gorm:"not null;default:0"`
	LastLoginAt  int64  `json:"lastLoginAt" gorm:"not null;default:0"`
	CreatedAt    int64  `json:"createdAt" gorm:"autoCreateTime"`
}

// TOTPEnabled reports whether the admin signs in with a second factor.
func (a Admin) TOTPEnabled() bool { return a.TOTPSecret != "" }

// Session is one sign-in, by its token's hash.
type Session struct {
	ID        uint   `gorm:"primaryKey"`
	TokenHash string `gorm:"uniqueIndex;not null"`
	AdminID   uint   `gorm:"index;not null"`
	ExpiresAt int64  `gorm:"not null"`
}

// All is every table, for the migration.
func All() []any {
	return []any{&PathHour{}, &PathDay{}, &TunnelHour{}, &NodeNetinfo{}, &State{}, &Admin{}, &Session{}}
}
