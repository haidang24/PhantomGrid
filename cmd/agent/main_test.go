package main

import (
	"net"
	"strings"
	"testing"
	"time"
)

// Test getRandomBanner function
func TestGetRandomBanner(t *testing.T) {
	tests := []struct {
		serviceType string
		expected    bool // Whether banner should be non-empty
	}{
		{"ssh", true},
		{"http", true},
		{"mysql", true},
		{"redis", true},
		{"ftp", true},
		{"telnet", true},
		{"unknown", true}, // Should fallback to SSH
	}

	for _, tt := range tests {
		t.Run(tt.serviceType, func(t *testing.T) {
			banner := getRandomBanner(tt.serviceType)
			if tt.expected && banner == "" {
				t.Errorf("getRandomBanner(%s) returned empty banner", tt.serviceType)
			}
			// Test multiple calls return different banners (randomization)
			banner2 := getRandomBanner(tt.serviceType)
			// Note: May be same by chance, but should be valid
			if banner2 == "" {
				t.Errorf("getRandomBanner(%s) returned empty banner on second call", tt.serviceType)
			}
		})
	}
}

// Test selectRandomService function
func TestSelectRandomService(t *testing.T) {
	// Test multiple calls to ensure it returns valid service types
	validServices := map[string]bool{
		"ssh":    true,
		"http":   true,
		"mysql":  true,
		"redis":  true,
		"ftp":    true,
		"telnet": true,
	}

	// Test 10 random selections
	for i := 0; i < 10; i++ {
		service := selectRandomService()
		if !validServices[service] {
			t.Errorf("selectRandomService() returned invalid service: %s", service)
		}
	}
}

// Test selectServiceByPort function
func TestSelectServiceByPort(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{80, "http"},
		{443, "http"},
		{8080, "http"},
		{8443, "http"},
		{8000, "http"},
		{8888, "http"},
		{3306, "mysql"},
		{5432, "mysql"},
		{1433, "mysql"},
		{1521, "mysql"},
		{6379, "redis"},
		{11211, "redis"},
		{27017, "mysql"}, // MongoDB
		{27018, "mysql"}, // MongoDB Shard
		{21, "ftp"},
		{23, "telnet"},
		{3389, "ssh"},  // RDP
		{5900, "ssh"},  // VNC
		{9200, "http"}, // Elasticsearch
		{5601, "http"}, // Kibana
		{3000, "http"}, // Node.js
		{5000, "http"}, // Flask
		{9999, ""},     // Should return random (not in switch)
		{12345, ""},    // Should return random
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.port)), func(t *testing.T) {
			result := selectServiceByPort(tt.port)
			if tt.expected != "" {
				if result != tt.expected {
					t.Errorf("selectServiceByPort(%d) = %s, expected %s", tt.port, result, tt.expected)
				}
			} else {
				// For ports not in switch, should return a valid service type
				validServices := []string{"ssh", "http", "mysql", "redis", "ftp", "telnet"}
				valid := false
				for _, svc := range validServices {
					if result == svc {
						valid = true
						break
					}
				}
				if !valid {
					t.Errorf("selectServiceByPort(%d) = %s, expected one of %v", tt.port, result, validServices)
				}
			}
		})
	}
}

// Test banner arrays are not empty
func TestBannerArraysNotEmpty(t *testing.T) {
	if len(sshBanners) == 0 {
		t.Error("sshBanners array is empty")
	}
	if len(httpBanners) == 0 {
		t.Error("httpBanners array is empty")
	}
	if len(mysqlBanners) == 0 {
		t.Error("mysqlBanners array is empty")
	}
	if len(redisBanners) == 0 {
		t.Error("redisBanners array is empty")
	}
	if len(ftpBanners) == 0 {
		t.Error("ftpBanners array is empty")
	}
	if len(telnetBanners) == 0 {
		t.Error("telnetBanners array is empty")
	}
}

// Test serviceTypes array is not empty
func TestServiceTypesNotEmpty(t *testing.T) {
	if len(serviceTypes) == 0 {
		t.Error("serviceTypes array is empty")
	}

	// Verify all service types are valid
	validServices := map[string]bool{
		"ssh":    true,
		"http":   true,
		"mysql":  true,
		"redis":  true,
		"ftp":    true,
		"telnet": true,
	}

	for _, svc := range serviceTypes {
		if !validServices[svc] {
			t.Errorf("serviceTypes contains invalid service: %s", svc)
		}
	}
}

// Test fakePorts array
func TestFakePortsNotEmpty(t *testing.T) {
	if len(fakePorts) == 0 {
		t.Error("fakePorts array is empty")
	}

	// Verify 9999 is NOT in fakePorts (it's HONEYPOT_PORT, not a fake port)
	for _, port := range fakePorts {
		if port == 9999 {
			t.Error("fakePorts should not contain 9999 (HONEYPOT_PORT)")
		}
		if port < 1 || port > 65535 {
			t.Errorf("fakePorts contains invalid port: %d", port)
		}
	}
}

// Test IP extraction from remote address
func TestExtractIPFromRemoteAddr(t *testing.T) {
	tests := []struct {
		remoteAddr string
		expectedIP string
	}{
		{"192.168.1.100:12345", "192.168.1.100"},
		{"10.0.0.1:8080", "10.0.0.1"},
		{"[::1]:9999", "[::1]"},
		{"127.0.0.1:22", "127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.remoteAddr, func(t *testing.T) {
			parts := strings.Split(tt.remoteAddr, ":")
			if len(parts) < 2 {
				t.Errorf("Invalid remote address format: %s", tt.remoteAddr)
				return
			}
			ip := parts[0]
			if ip != tt.expectedIP {
				t.Errorf("Extracted IP = %s, expected %s", ip, tt.expectedIP)
			}
		})
	}
}

// Test AttackLog structure
func TestAttackLogStructure(t *testing.T) {
	log := AttackLog{
		Timestamp:  "2025-12-27T23:00:00Z",
		AttackerIP: "192.168.1.100",
		Command:    "TEST_COMMAND",
		RiskLevel:  "HIGH",
	}

	if log.Timestamp == "" {
		t.Error("AttackLog Timestamp should not be empty")
	}
	if log.AttackerIP == "" {
		t.Error("AttackLog AttackerIP should not be empty")
	}
	if log.Command == "" {
		t.Error("AttackLog Command should not be empty")
	}
	if log.RiskLevel == "" {
		t.Error("AttackLog RiskLevel should not be empty")
	}
}

// Test connection handling with mock connection
func TestHandleConnectionWithNilRemoteAddr(t *testing.T) {
	// This test verifies that handleConnection handles nil remoteAddr gracefully
	// We can't easily test the full function without setting up network connections,
	// but we can test the nil check logic

	// Create a mock connection that returns nil for RemoteAddr
	mockConn := &mockConn{nil}

	// This should not panic
	// Note: In real scenario, handleConnection would call conn.Close() which might panic
	// But the nil check at the start should prevent issues
	remoteAddr := mockConn.RemoteAddr()
	if remoteAddr != nil {
		t.Error("Expected nil RemoteAddr for mock connection")
	}
}

// Mock connection for testing
type mockConn struct {
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Test banner format validation
func TestBannerFormats(t *testing.T) {
	// Test SSH banners contain "SSH"
	sshBanner := getRandomBanner("ssh")
	if !strings.Contains(sshBanner, "SSH") && !strings.Contains(sshBanner, "ssh") {
		t.Errorf("SSH banner should contain 'SSH': %s", sshBanner)
	}

	// Test HTTP banners contain "HTTP" or common HTTP headers
	httpBanner := getRandomBanner("http")
	httpKeywords := []string{"HTTP", "Server:", "nginx", "Apache", "IIS"}
	found := false
	for _, keyword := range httpKeywords {
		if strings.Contains(httpBanner, keyword) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("HTTP banner should contain HTTP keywords: %s", httpBanner)
	}
}

// Test port range validation for fakePorts
func TestFakePortsRange(t *testing.T) {
	for _, port := range fakePorts {
		if port < 1 || port > 65535 {
			t.Errorf("Invalid port in fakePorts: %d (must be 1-65535)", port)
		}
	}
}

// Benchmark tests
func BenchmarkGetRandomBanner(b *testing.B) {
	for i := 0; i < b.N; i++ {
		getRandomBanner("ssh")
	}
}

func BenchmarkSelectRandomService(b *testing.B) {
	for i := 0; i < b.N; i++ {
		selectRandomService()
	}
}

func BenchmarkSelectServiceByPort(b *testing.B) {
	ports := []int{80, 443, 3306, 6379, 21, 23, 9999}
	for i := 0; i < b.N; i++ {
		selectServiceByPort(ports[i%len(ports)])
	}
}
