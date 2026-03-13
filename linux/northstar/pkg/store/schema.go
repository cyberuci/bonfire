package store

import "time"

type Network struct {
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"uniqueIndex"`
	CIDR        string
	Description string
}

type Host struct {
	ID              uint `gorm:"primaryKey"`
	Hostname        string
	IP              string
	OSType          string
	OSVersion       string
	Role            string
	PasswordIndex   *int
	FirewallEnabled bool `gorm:"default:false"`
	NetworkID       *uint
	Network         *Network   `gorm:"foreignKey:NetworkID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	HostPorts       []HostPort `gorm:"foreignKey:HostID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Services        []Service  `gorm:"foreignKey:HostID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type HostPort struct {
	HostID      uint   `gorm:"primaryKey"`
	Port        uint16 `gorm:"primaryKey"`
	Whitelisted bool
}

type Service struct {
	ID                 uint `gorm:"primaryKey;column:service_id"`
	HostID             uint
	Name               string
	Technology         string
	Scored             bool
	Disabled           bool
	BackedUp           bool
	Hardened           bool
	LDAPAuthentication bool
	PasswordIndex      *int
	ServicePorts       []ServicePort       `gorm:"foreignKey:ServiceID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Websites           []Website           `gorm:"foreignKey:ServiceID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Dependencies       []ServiceDependency `gorm:"foreignKey:ServiceID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type ServiceDependency struct {
	ServiceID        uint    `gorm:"primaryKey"`
	DependsOnID      uint    `gorm:"primaryKey"`
	DependsOnService Service `gorm:"foreignKey:DependsOnID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type ServicePort struct {
	ServiceID uint   `gorm:"primaryKey"`
	Port      uint16 `gorm:"primaryKey"`
}

type Website struct {
	ID            uint `gorm:"primaryKey;column:website_id"`
	ServiceID     *uint
	Name          string
	URL           string
	Username      string
	PasswordIndex *int
	OldPassword   string
	Enumerated    bool `gorm:"default:false"`
}

type PasswordEntry struct {
	ID       uint `gorm:"primaryKey"`
	Index    int  `gorm:"uniqueIndex"`
	Category string
	Comment  string
}

type Inject struct {
	ID            uint `gorm:"primaryKey"`
	Number        string
	Title         string
	Description   string
	Content       string
	Due           time.Time
	Assignees     []Assignee `gorm:"foreignKey:InjectID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Completed     bool
	SubmissionURL string
}

type Assignee struct {
	ID       uint `gorm:"primaryKey"`
	Name     string
	InjectID uint
}

type File struct {
	ID          uint `gorm:"primaryKey"`
	Name        string
	Size        int64
	URL         string
	Description string
	UploadedAt  time.Time `gorm:"autoCreateTime"`
}

type AllowedIP struct {
	ID          uint   `gorm:"primaryKey"`
	CIDR        string `gorm:"uniqueIndex"`
	Description string
}
