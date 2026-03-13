package store_test

import (
	"testing"

	"bonfire/northstar/pkg/store"
)

func TestStore(t *testing.T) {

	db, err := store.New("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	host := store.Host{
		Hostname:        "web-server-01",
		IP:              "192.168.1.10",
		OSType:          "Linux",
		OSVersion:       "Ubuntu 22.04",
		Role:            "Web Server",
		FirewallEnabled: true,
		HostPorts: []store.HostPort{
			{Port: 22, Whitelisted: true},
			{Port: 80, Whitelisted: true},
			{Port: 443, Whitelisted: true},
		},
	}

	result := db.Create(&host)
	if result.Error != nil {
		t.Fatalf("failed to create host: %v", result.Error)
	}
	t.Logf("Created Host: %s (ID: %d)", host.Hostname, host.ID)

	service := store.Service{
		HostID:     host.ID,
		Name:       "Nginx",
		Technology: "Web Server",
		Scored:     true,
		Disabled:   false,
		ServicePorts: []store.ServicePort{
			{Port: 80},
			{Port: 443},
		},
	}

	result = db.Create(&service)
	if result.Error != nil {
		t.Fatalf("failed to create service: %v", result.Error)
	}
	t.Logf("Created Service: %s (ID: %d)", service.Name, service.ID)

	website := store.Website{
		ServiceID:   &service.ID,
		Name:        "My Blog",
		URL:         "http://192.168.1.10:80",
		Username:    "admin",
		OldPassword: "admin123",
	}

	result = db.Create(&website)
	if result.Error != nil {
		t.Fatalf("failed to create website: %v", result.Error)
	}
	t.Logf("Created Website: %s (ID: %d)", website.Name, website.ID)

	var retrievedHost store.Host

	result = db.Preload("HostPorts").Preload("Services.ServicePorts").Preload("Services.Websites").First(&retrievedHost, host.ID)
	if result.Error != nil {
		t.Fatalf("failed to retrieve host: %v", result.Error)
	}

	t.Logf("\nRetrieved Host: %s", retrievedHost.Hostname)
	if len(retrievedHost.HostPorts) != 3 {
		t.Errorf("Expected 3 HostPorts, got %d", len(retrievedHost.HostPorts))
	}
	for _, hp := range retrievedHost.HostPorts {
		t.Logf("  HostPort: %d (Whitelisted: %v)", hp.Port, hp.Whitelisted)
	}

	for _, s := range retrievedHost.Services {
		t.Logf("  Service: %s", s.Name)
		if len(s.ServicePorts) != 2 {
			t.Errorf("Expected 2 ServicePorts for service %s, got %d", s.Name, len(s.ServicePorts))
		}
		for _, sp := range s.ServicePorts {
			t.Logf("    ServicePort: %d", sp.Port)
		}
		for _, w := range s.Websites {
			t.Logf("    Website: %s (%s)", w.Name, w.URL)
		}
	}
}
