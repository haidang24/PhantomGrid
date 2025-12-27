package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	ui "github.com/gizak/termui/v3"
	"github.com/gizak/termui/v3/widgets"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Phantom ../../bpf/phantom.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go Egress ../../bpf/phantom_egress.c

// Log Channel for TUI
var logChan = make(chan string, 100)

// Fake Banner Database - "The Mirage" Module
var (
	sshBanners = []string{
		"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
		"SSH-2.0-OpenSSH_7.4 Debian-10+deb9u7\r\n",
		"SSH-2.0-OpenSSH_8.0 FreeBSD-20200214\r\n",
		"SSH-2.0-OpenSSH_7.9 CentOS-7.9\r\n",
		"SSH-2.0-OpenSSH_8.1 RedHat-8.1\r\n",
		"SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u4\r\n",
		"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n",
		"SSH-2.0-OpenSSH_8.4p1 Arch Linux\r\n",
	}

	httpBanners = []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Debian)\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.20.1\r\n\r\n",
	}

	mysqlBanners = []string{
		"\x0a5.7.35-0ubuntu0.18.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a8.0.27-0ubuntu0.20.04.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		"\x0a10.3.34-MariaDB-1:10.3.34+maria~focal\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	}

	redisBanners = []string{
		"$6\r\nRedis\r\n",
		"$7\r\nRedis 6.2.6\r\n",
		"$7\r\nRedis 5.0.7\r\n",
	}

	ftpBanners = []string{
		"220 ProFTPD 1.3.6 Server (ProFTPD Default Installation) [::ffff:192.168.1.1]\r\n",
		"220 (vsFTPd 3.0.3)\r\n",
		"220 Microsoft FTP Service\r\n",
	}

	telnetBanners = []string{
		"Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n\r\n* Documentation:  https://help.ubuntu.com\r\n* Management:     https://landscape.canonical.com\r\n* Support:        https://ubuntu.com/advantage\r\n\r\n  System information as of ",
		"Red Hat Enterprise Linux Server release 7.9 (Maipo)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlogin: ",
		"CentOS Linux 7 (Core)\r\nKernel 3.10.0-1160.el7.x86_64 on an x86_64\r\n\r\nlocalhost login: ",
		"Debian GNU/Linux 10\r\n\r\nlocalhost login: ",
	}

	// Service type probabilities (for randomization) - The Mirage effect
	// Mỗi kết nối sẽ nhận được một dịch vụ ngẫu nhiên, tạo "Ghost Grid"
	serviceTypes = []string{"ssh", "http", "mysql", "redis", "ftp", "telnet"}
)

// AttackLog is the structured format used by the Shadow Recorder
type AttackLog struct {
	Timestamp  string `json:"timestamp"`
	AttackerIP string `json:"src_ip"`
	Command    string `json:"command"`
	RiskLevel  string `json:"risk_level"`
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	// Parse command line arguments
	interfaceFlag := flag.String("interface", "", "Network interface name (e.g., eth0, ens33, wlx00127b2163a6). If not specified, auto-detect will be used.")
	flag.Parse()

	// 1. Initialize System
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("[!] Failed to lock memory:", err)
	}

	// 2. Load eBPF Programs
	objs := PhantomObjects{}
	if err := LoadPhantomObjects(&objs, nil); err != nil {
		log.Fatal("[!] Failed to load eBPF objects:", err)
	}
	defer objs.Close()

	// 3. Attach XDP to Interface
	ifaceName := ""
	var iface *net.Interface
	var err error

	// List tất cả interfaces để debug
	allInterfaces, _ := net.Interfaces()
	log.Printf("[DEBUG] Available interfaces:")
	for _, iface := range allInterfaces {
		addrs, _ := iface.Addrs()
		isLoopback := (iface.Flags & net.FlagLoopback) != 0
		log.Printf("[DEBUG]   - %s (index: %d, loopback: %v, addrs: %d)", iface.Name, iface.Index, isLoopback, len(addrs))
		for _, addr := range addrs {
			log.Printf("[DEBUG]     IP: %s", addr.String())
		}
	}

	// Nếu user chỉ định interface từ command line, sử dụng nó
	if *interfaceFlag != "" {
		iface, err = net.InterfaceByName(*interfaceFlag)
		if err != nil {
			log.Fatalf("[!] Failed to find interface '%s': %v\n[!] Available interfaces listed above.", *interfaceFlag, err)
		}
		ifaceName = *interfaceFlag
		log.Printf("[*] Using user-specified interface: %s (index: %d)", ifaceName, iface.Index)
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			log.Printf("[*]   IP: %s", addr.String())
		}
	} else {
		// Auto-detect interface (logic cũ)
		log.Printf("[*] No interface specified, auto-detecting...")

		// Try common interface names - ưu tiên external interface trước
		// Để "The Mirage" hoạt động, cần attach vào interface nhận traffic từ bên ngoài
		// Ưu tiên WiFi interface (wlx*), sau đó ens33 (VMware), rồi các interface khác
		interfaceNames := []string{"wlx00127b2163a6", "wlan0", "ens33", "eth0", "enp0s3", "enp0s8", "enp0s9", "eth1"}
		var foundExternal bool

		// First, try to find WiFi interface by pattern (wlx*, wlan*, wlp*)
		wifiInterfaces, _ := net.Interfaces()
		for _, candidateIface := range wifiInterfaces {
			if strings.HasPrefix(candidateIface.Name, "wlx") ||
				strings.HasPrefix(candidateIface.Name, "wlan") ||
				strings.HasPrefix(candidateIface.Name, "wlp") {
				addrs, _ := candidateIface.Addrs()
				if len(addrs) > 0 {
					isLoopback := (candidateIface.Flags & net.FlagLoopback) != 0
					if !isLoopback {
						// Create a copy to avoid pointer issues
						ifaceCopy := candidateIface
						iface = &ifaceCopy
						ifaceName = candidateIface.Name
						foundExternal = true
						log.Printf("[*] Found WiFi interface: %s (index: %d)", ifaceName, iface.Index)
						for _, addr := range addrs {
							log.Printf("[*]   IP: %s", addr.String())
						}
						break
					}
				}
			}
		}

		// If WiFi not found, try exact interface names
		if !foundExternal {
			for _, name := range interfaceNames {
				iface, err = net.InterfaceByName(name)
				if err == nil {
					// Kiểm tra xem interface có IP address không (không phải loopback)
					addrs, _ := iface.Addrs()
					if len(addrs) > 0 {
						// Kiểm tra xem có phải loopback không
						isLoopback := (iface.Flags & net.FlagLoopback) != 0
						if !isLoopback {
							ifaceName = name
							foundExternal = true
							log.Printf("[*] Using network interface: %s (index: %d)", ifaceName, iface.Index)
							// Log IP addresses
							for _, addr := range addrs {
								log.Printf("[*]   IP: %s", addr.String())
							}
							break
						} else {
							log.Printf("[DEBUG] Interface %s is loopback, skipping", name)
						}
					} else {
						log.Printf("[DEBUG] Interface %s has no IP addresses, skipping", name)
					}
				} else {
					log.Printf("[DEBUG] Interface %s not found: %v", name, err)
				}
			}
		}

		// Fallback to loopback nếu không tìm thấy external interface
		if !foundExternal {
			iface, err = net.InterfaceByName("lo")
			if err == nil {
				ifaceName = "lo"
				log.Printf("[*] Using loopback interface: %s (index: %d) - for local testing only", ifaceName, iface.Index)
				log.Printf("[!] WARNING: For production, attach to external interface (eth0, ens33, etc.)")
				log.Printf("[!] WARNING: Traffic from external hosts (Kali) will NOT be captured on loopback!")
			}
		}

		if ifaceName == "" {
			log.Fatal("[!] No suitable network interface found. Please check your network configuration.")
		}
	}

	// Attach XDP to detected interface
	// CHỈ attach vào interface chính để tránh conflict và treo máy
	// Sử dụng XDPGenericMode để tương thích tốt hơn với VMware và các virtual interfaces
	// Generic mode chạy trong kernel network stack, tương thích tốt hơn Native mode
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PhantomProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // QUAN TRỌNG: Generic mode cho VMware compatibility
	})
	if err != nil {
		log.Fatal("[!] Failed to attach XDP:", err)
	}
	defer l.Close()

	log.Printf("[*] XDP attached to interface: %s (index: %d)", ifaceName, iface.Index)

	// 3.1 Load and attach TC Egress Program (DLP) using netlink
	// Note: TC Egress requires specific netlink APIs that may not be available on all systems
	// If compilation fails with netlink.QdiscAdd/FilterAdd errors, TC Egress DLP will be disabled
	// The main XDP-based protection (Phantom Protocol, The Mirage, The Portal) will still work
	var egressObjs EgressObjects
	var egressObjsPtr *EgressObjects

	if err := LoadEgressObjects(&egressObjs, nil); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects: %v", err)
		log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
	} else {
		// Setup TC Egress using netlink
		if err := attachTCEgress(iface, &egressObjs); err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
			log.Printf("[!] TC Egress DLP will be disabled. Main XDP protection still active.")
			egressObjs.Close()
			egressObjsPtr = nil
		} else {
			// Success
			egressObjsPtr = &egressObjs
			logChan <- "[SYSTEM] TC Egress Hook attached (DLP Active)"

			defer func() {
				egressObjs.Close()
			}()
		}
	}

	// 3.2 Start SPA Whitelist Manager
	go manageSPAWhitelist(&objs)

	// Log interface info for debugging
	logChan <- fmt.Sprintf("[SYSTEM] XDP attached to interface: %s (index: %d)", ifaceName, iface.Index)
	logChan <- fmt.Sprintf("[SYSTEM] SPA Magic Packet port: 1337")
	logChan <- fmt.Sprintf("[SYSTEM] SSH port 22 protected - requires SPA whitelist")

	// Debug: Log interface IP addresses
	addrs, _ := iface.Addrs()
	for _, addr := range addrs {
		logChan <- fmt.Sprintf("[DEBUG] Interface %s has IP: %s", ifaceName, addr.String())
	}

	// Warning nếu attach vào loopback
	if ifaceName == "lo" {
		logChan <- "[!] WARNING: XDP attached to LOOPBACK interface!"
		logChan <- "[!] WARNING: Traffic from external hosts (Kali) will NOT be captured!"
		logChan <- "[!] WARNING: For VMware NAT, ensure XDP attaches to external interface (ens33, eth0, etc.)"
		logChan <- "[!] WARNING: Check if interface detection is working correctly"
	}

	// 4. Start Internal Honeypot
	go startHoneypot()

	// 5. Start Dashboard
	startDashboard(ifaceName, &objs, egressObjsPtr)
}

// Helper function to attach TC Egress using netlink
func attachTCEgress(iface *net.Interface, objs *EgressObjects) error {
	// FIX: Sử dụng _ để bỏ qua biến không dùng, tránh lỗi "declared and not used"
	_, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return fmt.Errorf("could not get link: %v", err)
	}

	// 1. Add clsact qdisc (allows attaching BPF to ingress/egress)
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	// Try to add qdisc, ignore if already exists
	if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		// Just log, might fail if already exists which is fine
		// Return error only if it's a real error (not "already exists")
		return fmt.Errorf("failed to add qdisc: %v", err)
	}

	// 2. Add BPF Filter to Egress
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS, // Egress hook
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           objs.PhantomEgressProg.FD(),
		Name:         "phantom_egress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("failed to add filter: %v", err)
	}

	return nil
}

// manageSPAWhitelist periodically checks SPA statistics and logs changes
// Note: SPA whitelist expiry (30 seconds) is handled by eBPF LRU map auto-eviction
// The eBPF program uses LRU hash map which will automatically evict old entries
func manageSPAWhitelist(objs *PhantomObjects) {
	ticker := time.NewTicker(2 * time.Second)
	var lastSuccessCount uint64 = 0
	var lastFailedCount uint64 = 0

	for range ticker.C {
		// Check SPA auth success counter
		var key uint32 = 0
		var successVal uint64
		if err := objs.SpaAuthSuccess.Lookup(key, &successVal); err == nil {
			if successVal > lastSuccessCount {
				logChan <- fmt.Sprintf("[SPA] ✅ Successful authentication! (Total: %d)", successVal)
				logChan <- fmt.Sprintf("[SPA] ⏱️  IP whitelisted for 30 seconds (LRU map auto-expiry)")
				lastSuccessCount = successVal
			}
		}

		// Check SPA auth failed counter
		var failedVal uint64
		if err := objs.SpaAuthFailed.Lookup(key, &failedVal); err == nil {
			if failedVal > lastFailedCount {
				logChan <- fmt.Sprintf("[SPA] ❌ Failed authentication attempt (Total: %d)", failedVal)
				lastFailedCount = failedVal
			}
		}
	}
}

// logAttack writes a structured AttackLog entry
func logAttack(ip string, cmd string) {
	entry := AttackLog{
		Timestamp:  time.Now().Format(time.RFC3339),
		AttackerIP: ip,
		Command:    cmd,
		RiskLevel:  "HIGH",
	}
	if err := os.MkdirAll("logs", 0o755); err != nil {
		return
	}
	file, err := os.OpenFile("logs/audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		// Silent fail for logging errors
		_ = err
	}
}

// --- DASHBOARD UI ---
func startDashboard(iface string, objs *PhantomObjects, egressObjs *EgressObjects) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	startTime := time.Now()

	// Thread-safe statistics
	var statsMutex sync.RWMutex
	honeypotConnections := uint64(0)
	totalCommands := uint64(0)
	activeSessions := uint64(0)

	// Get terminal dimensions
	termWidth, termHeight := ui.TerminalDimensions()
	if termWidth < 100 {
		termWidth = 100
	}
	if termHeight < 30 {
		termHeight = 30
	}

	// Header with enhanced information
	header := widgets.NewParagraph()
	header.Title = " ═══ PHANTOM GRID - ACTIVE DEFENSE SYSTEM ═══ "
	header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [00:00:00](fg:cyan)", iface)
	header.SetRect(0, 0, termWidth, 3)
	header.TextStyle.Fg = ui.ColorCyan
	header.BorderStyle.Fg = ui.ColorCyan

	// Real-time forensics log (left side, larger)
	logList := widgets.NewList()
	logList.Title = " ═══ REAL-TIME FORENSICS & EVENT LOG (j/k: scroll, a: auto-scroll, G: bottom) ═══ "
	logList.Rows = []string{
		"[SYSTEM] Phantom Grid initialized...",
		"[SYSTEM] eBPF XDP Hook attached...",
		"[SYSTEM] TC Egress Hook attached (DLP Active)...",
		"[SYSTEM] Honeypot service listening on port 9999...",
		"[SYSTEM] Dashboard ready. Monitoring traffic...",
		"[HELP] Use 'j'/'k' to scroll, 'G' to go to bottom, 'a' to toggle auto-scroll",
	}
	logList.SetRect(0, 3, termWidth/2+10, termHeight-8)
	logList.TextStyle.Fg = ui.ColorGreen
	logList.SelectedRowStyle.Fg = ui.ColorWhite
	logList.SelectedRowStyle.Bg = ui.ColorBlue
	logList.BorderStyle.Fg = ui.ColorGreen

	// Threat Level Gauge
	gauge := widgets.NewGauge()
	gauge.Title = " ═══ THREAT LEVEL ═══ "
	gauge.Percent = 0
	gauge.SetRect(termWidth/2+10, 3, termWidth, 6)
	gauge.BarColor = ui.ColorGreen
	gauge.Label = "0%"
	gauge.BorderStyle.Fg = ui.ColorYellow

	// Statistics Section - Row 1
	redirectedBox := widgets.NewParagraph()
	redirectedBox.Title = " ═══ REDIRECTED TO HONEYPOT ═══ "
	redirectedBox.Text = "\n\n       0"
	redirectedBox.SetRect(termWidth/2+10, 6, termWidth/2+25, 11)
	redirectedBox.TextStyle.Fg = ui.ColorYellow
	redirectedBox.BorderStyle.Fg = ui.ColorYellow

	stealthBox := widgets.NewParagraph()
	stealthBox.Title = " ═══ STEALTH SCAN DROPS ═══ "
	stealthBox.Text = "\n\n       0"
	stealthBox.SetRect(termWidth/2+25, 6, termWidth/2+40, 11)
	stealthBox.TextStyle.Fg = ui.ColorRed
	stealthBox.BorderStyle.Fg = ui.ColorRed

	egressBox := widgets.NewParagraph()
	egressBox.Title = " ═══ EGRESS BLOCKS (DLP) ═══ "
	egressBox.Text = "\n\n       0"
	egressBox.SetRect(termWidth/2+40, 6, termWidth, 11)
	egressBox.TextStyle.Fg = ui.ColorMagenta
	egressBox.BorderStyle.Fg = ui.ColorMagenta

	// Statistics Section - Row 2
	osMutationsBox := widgets.NewParagraph()
	osMutationsBox.Title = " ═══ OS PERSONALITY MUTATIONS ═══ "
	osMutationsBox.Text = "\n\n       0"
	osMutationsBox.SetRect(termWidth/2+10, 11, termWidth/2+25, 16)
	osMutationsBox.TextStyle.Fg = ui.ColorCyan
	osMutationsBox.BorderStyle.Fg = ui.ColorCyan

	spaSuccessBox := widgets.NewParagraph()
	spaSuccessBox.Title = " ═══ SPA AUTH SUCCESS ═══ "
	spaSuccessBox.Text = "\n\n       0"
	spaSuccessBox.SetRect(termWidth/2+25, 11, termWidth/2+40, 16)
	spaSuccessBox.TextStyle.Fg = ui.ColorGreen
	spaSuccessBox.BorderStyle.Fg = ui.ColorGreen

	spaFailedBox := widgets.NewParagraph()
	spaFailedBox.Title = " ═══ SPA AUTH FAILED ═══ "
	spaFailedBox.Text = "\n\n       0"
	spaFailedBox.SetRect(termWidth/2+40, 11, termWidth, 16)
	spaFailedBox.TextStyle.Fg = ui.ColorRed
	spaFailedBox.BorderStyle.Fg = ui.ColorRed

	// System Information Section
	systemInfoBox := widgets.NewParagraph()
	systemInfoBox.Title = " ═══ SYSTEM INFORMATION ═══ "
	egressStatus := "INACTIVE"
	egressColor := "red"
	if egressObjs != nil {
		egressStatus = "ACTIVE"
		egressColor = "green"
	}
	systemInfoBox.Text = fmt.Sprintf("\nInterface: %s\nXDP Hook: [ACTIVE](fg:green)\nTC Egress: [%s](fg:%s)\nHoneypot: [LISTENING](fg:green)\nPort: 9999\nSPA Port: 1337\nSSH Port: 22 (Protected)",
		iface, egressStatus, egressColor)
	systemInfoBox.SetRect(termWidth/2+10, 16, termWidth, termHeight-8)
	systemInfoBox.BorderStyle.Fg = ui.ColorBlue

	// Connection Statistics
	connStatsBox := widgets.NewParagraph()
	connStatsBox.Title = " ═══ CONNECTION STATISTICS ═══ "
	connStatsBox.Text = "\n\nHoneypot Connections: 0\nActive Sessions: 0\nTotal Commands: 0"
	connStatsBox.SetRect(0, termHeight-8, termWidth/2+10, termHeight-3)
	connStatsBox.BorderStyle.Fg = ui.ColorMagenta

	// Footer with instructions
	footer := widgets.NewParagraph()
	footer.Title = " CONTROLS "
	footer.Text = "Press [q](fg:yellow) or [Ctrl+C](fg:yellow) to exit | [SPACE](fg:yellow) to pause/resume logs"
	footer.SetRect(0, termHeight-3, termWidth, termHeight)
	footer.BorderStyle.Fg = ui.ColorWhite

	// Initial render
	ui.Render(header, logList, gauge, redirectedBox, stealthBox, egressBox,
		osMutationsBox, spaSuccessBox, spaFailedBox, systemInfoBox, connStatsBox, footer)

	ticker := time.NewTicker(200 * time.Millisecond)
	statsTicker := time.NewTicker(1 * time.Second)
	uptimeTicker := time.NewTicker(1 * time.Second)
	uiEvents := ui.PollEvents()
	threatCount := 0
	paused := false

	// Update uptime
	go func() {
		for range uptimeTicker.C {
			uptime := time.Since(startTime)
			hours := int(uptime.Hours())
			minutes := int(uptime.Minutes()) % 60
			seconds := int(uptime.Seconds()) % 60
			header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red) | UPTIME: [%02d:%02d:%02d](fg:cyan)",
				iface, hours, minutes, seconds)
			ui.Render(header)
		}
	}()

	// Track previous attack stats to detect new connections
	var lastAttackCount uint64 = 0

	// Update statistics
	go func() {
		for range statsTicker.C {
			var attackKey uint32 = 0
			var attackVal uint64
			if err := objs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
				redirectedBox.Text = fmt.Sprintf("\n\n   %d", attackVal)

				// Debug: Log when attack stats increase (XDP detected packets)
				if attackVal > lastAttackCount {
					newAttacks := attackVal - lastAttackCount
					if newAttacks > 0 {
						logChan <- fmt.Sprintf("[DEBUG] XDP detected %d new SYN packets to fake ports (Total: %d)", newAttacks, attackVal)
					}
					lastAttackCount = attackVal
				}
			}

			var stealthKey uint32 = 0
			var stealthVal uint64
			if err := objs.StealthDrops.Lookup(stealthKey, &stealthVal); err == nil {
				stealthBox.Text = fmt.Sprintf("\n\n   %d", stealthVal)
			}

			var osKey uint32 = 0
			var osVal uint64
			if err := objs.OsMutations.Lookup(osKey, &osVal); err == nil {
				osMutationsBox.Text = fmt.Sprintf("\n\n   %d", osVal)
			}

			var spaSuccessKey uint32 = 0
			var spaSuccessVal uint64
			if err := objs.SpaAuthSuccess.Lookup(spaSuccessKey, &spaSuccessVal); err == nil {
				spaSuccessBox.Text = fmt.Sprintf("\n\n   %d", spaSuccessVal)
			}

			var spaFailedKey uint32 = 0
			var spaFailedVal uint64
			if err := objs.SpaAuthFailed.Lookup(spaFailedKey, &spaFailedVal); err == nil {
				spaFailedBox.Text = fmt.Sprintf("\n\n   %d", spaFailedVal)
			}

			if egressObjs != nil && egressObjs.EgressBlocks != nil {
				var egressKey uint32 = 0
				var egressVal uint64
				if err := egressObjs.EgressBlocks.Lookup(egressKey, &egressVal); err == nil {
					egressBox.Text = fmt.Sprintf("\n\n   %d", egressVal)
				}
			}

			// Update connection statistics (thread-safe read)
			statsMutex.RLock()
			connCount := honeypotConnections
			sessionCount := activeSessions
			cmdCount := totalCommands
			statsMutex.RUnlock()

			connStatsBox.Text = fmt.Sprintf("\n\nHoneypot Connections: %d\nActive Sessions: %d\nTotal Commands: %d",
				connCount, sessionCount, cmdCount)

			// Calculate threat level based on multiple factors
			totalThreats := attackVal + stealthVal
			if totalThreats > 0 {
				threatLevel := int((totalThreats * 10) % 100)
				if threatLevel > 100 {
					threatLevel = 100
				}
				gauge.Percent = threatLevel
				if threatLevel < 30 {
					gauge.BarColor = ui.ColorGreen
					gauge.Label = fmt.Sprintf("%d%% - LOW", threatLevel)
				} else if threatLevel < 70 {
					gauge.BarColor = ui.ColorYellow
					gauge.Label = fmt.Sprintf("%d%% - MEDIUM", threatLevel)
				} else {
					gauge.BarColor = ui.ColorRed
					gauge.Label = fmt.Sprintf("%d%% - HIGH", threatLevel)
				}
			}

			ui.Render(redirectedBox, stealthBox, egressBox, osMutationsBox,
				spaSuccessBox, spaFailedBox, gauge, connStatsBox)
		}
	}()

	// Auto-scroll state
	autoScroll := true

	for {
		select {
		case e := <-uiEvents:
			if e.Type == ui.KeyboardEvent {
				switch e.ID {
				case "q", "<C-c>":
					return
				case " ":
					paused = !paused
					if paused {
						logChan <- "[SYSTEM] Log scrolling paused"
					} else {
						logChan <- "[SYSTEM] Log scrolling resumed"
					}
				case "j", "<Down>":
					// Scroll down
					logList.ScrollDown()
					autoScroll = false
					ui.Render(logList, connStatsBox)
				case "k", "<Up>":
					// Scroll up
					logList.ScrollUp()
					autoScroll = false
					ui.Render(logList, connStatsBox)
				case "g", "<Home>":
					// Scroll to top
					logList.ScrollTop()
					autoScroll = false
					ui.Render(logList, connStatsBox)
				case "G", "<End>":
					// Scroll to bottom (enable auto-scroll)
					logList.ScrollBottom()
					autoScroll = true
					ui.Render(logList, connStatsBox)
				case "a":
					// Toggle auto-scroll
					autoScroll = !autoScroll
					if autoScroll {
						logList.ScrollBottom()
						logChan <- "[SYSTEM] Auto-scroll enabled (press 'a' to disable)"
					} else {
						logChan <- "[SYSTEM] Auto-scroll disabled (press 'a' to enable, 'G' to go to bottom)"
					}
					ui.Render(logList, connStatsBox)
				}
			}
		case msg := <-logChan:
			if !paused {
				logList.Rows = append(logList.Rows, msg)
				// Keep more logs in memory (allow scrolling through history)
				maxLogs := (termHeight - 8) * 5 // Keep 5x visible area
				if len(logList.Rows) > maxLogs {
					logList.Rows = logList.Rows[len(logList.Rows)-maxLogs:]
				}
				// Only auto-scroll if enabled
				if autoScroll {
					logList.ScrollBottom()
				}
			}

			// Track statistics from log messages (thread-safe write)
			statsMutex.Lock()
			if strings.Contains(msg, "TRAP HIT") {
				honeypotConnections++
				activeSessions++
			}
			if strings.Contains(msg, "COMMAND") {
				totalCommands++
			}
			if strings.Contains(msg, "exit") {
				if activeSessions > 0 {
					activeSessions--
				}
			}
			statsMutex.Unlock()

			threatCount++
			ui.Render(logList, connStatsBox)
		case <-ticker.C:
			ui.Render(logList, connStatsBox)
		}
	}
}

// Fake Ports - "The Mirage": Các port giả mà honeypot sẽ bind
// Khi quét từ bên ngoài, nmap sẽ thấy các port này "mở"
// Fake Ports - The Mirage: Danh sách các port giả để honeypot bind
// LƯU Ý: 9999 là HONEYPOT_PORT (fallback), KHÔNG phải fake port
// Danh sách này phải khớp với is_fake_port() trong bpf/phantom.c
var fakePorts = []int{
	80,    // HTTP
	443,   // HTTPS
	3306,  // MySQL (fake)
	5432,  // PostgreSQL (fake)
	6379,  // Redis (fake)
	27017, // MongoDB (fake)
	8080,  // Admin Panel (fake)
	8443,  // HTTPS Alt (fake)
	9000,  // Admin Panel (fake)
	21,    // FTP (fake)
	23,    // Telnet (fake)
	3389,  // RDP (fake)
	5900,  // VNC (fake)
	1433,  // MSSQL (fake)
	1521,  // Oracle (fake)
	5433,  // PostgreSQL Alt (fake)
	11211, // Memcached (fake)
	27018, // MongoDB Shard (fake)
	9200,  // Elasticsearch (fake)
	5601,  // Kibana (fake)
	3000,  // Node.js (fake)
	5000,  // Flask (fake)
	8000,  // Django (fake)
	8888,  // Jupyter (fake)
	// 9999 is HONEYPOT_PORT (fallback), not a fake port
}

// --- HONEYPOT LOGIC ---
// "The Mirage": Bind nhiều port giả để tạo "Ghost Grid"
// Honeypot sẽ cố gắng bind tất cả các fake ports
// Nếu bind thành công, XDP sẽ pass packets đến port đó
// Nếu bind thất bại (port đã được sử dụng), XDP sẽ redirect đến port 9999 (fallback)
func startHoneypot() {
	var listeners []net.Listener
	var boundPorts []int
	var wg sync.WaitGroup

	// Cố gắng bind tất cả các port giả
	for _, port := range fakePorts {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			// Port có thể đã được sử dụng, log và skip
			// XDP sẽ redirect các port này đến 9999
			logChan <- fmt.Sprintf("[WARN] Cannot bind port %d: %v (XDP will redirect to 9999)", port, err)
			continue
		}
		listeners = append(listeners, ln)
		boundPorts = append(boundPorts, port)
		logChan <- fmt.Sprintf("[SYSTEM] Honeypot listening on port %d", port)

		wg.Add(1)
		go func(l net.Listener, p int) {
			defer wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					logChan <- fmt.Sprintf("[ERROR] Honeypot accept error on port %d: %v", p, err)
					continue
				}
				// Debug: Log when connection is accepted
				remoteAddr := conn.RemoteAddr()
				if remoteAddr != nil {
					logChan <- fmt.Sprintf("[DEBUG] Honeypot accepted connection on port %d from %s", p, remoteAddr.String())
				}
				// Bind trực tiếp, biết port gốc
				go handleConnection(conn, p)
			}
		}(ln, port)
	}

	// Fallback: Bind port 9999 cho các port không bind được
	// QUAN TRỌNG: Port 9999 phải available để XDP redirect hoạt động
	logChan <- "[SYSTEM] Attempting to bind honeypot fallback port 9999..."
	ln9999, err := net.Listen("tcp", ":9999")
	if err != nil {
		logChan <- fmt.Sprintf("[ERROR] Cannot bind port 9999: %v", err)
		logChan <- "[ERROR] Port 9999 is required for XDP redirect fallback!"
		logChan <- "[ERROR] To free port 9999, run: sudo lsof -i :9999 && sudo kill -9 <PID>"
		logChan <- "[ERROR] Or change HONEYPOT_PORT in bpf/phantom.c and rebuild"
		// Try alternative ports
		fallbackPorts := []int{9998, 9997, 9996, 8888, 7777}
		var fallbackListener net.Listener
		for _, altPort := range fallbackPorts {
			fallbackListener, err = net.Listen("tcp", fmt.Sprintf(":%d", altPort))
			if err == nil {
				logChan <- fmt.Sprintf("[WARN] Using alternative fallback port %d instead of 9999", altPort)
				logChan <- fmt.Sprintf("[WARN] NOTE: XDP is still redirecting to port 9999 - connections may fail!")
				listeners = append(listeners, fallbackListener)
				wg.Add(1)
				go func(l net.Listener, p int) {
					defer wg.Done()
					for {
						conn, err := l.Accept()
						if err != nil {
							logChan <- fmt.Sprintf("[ERROR] Honeypot accept error on port %d: %v", p, err)
							continue
						}
						remoteAddr := conn.RemoteAddr()
						if remoteAddr != nil {
							logChan <- fmt.Sprintf("[DEBUG] Honeypot accepted connection on port %d (alternative fallback) from %s", p, remoteAddr.String())
						}
						go handleConnection(conn, p)
					}
				}(fallbackListener, altPort)
				break
			}
		}
		if fallbackListener == nil {
			logChan <- "[ERROR] Failed to bind any fallback port!"
		}
	} else {
		listeners = append(listeners, ln9999)
		logChan <- "[SYSTEM] Honeypot listening on port 9999 (fallback for redirected ports)"

		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					logChan <- fmt.Sprintf("[ERROR] Honeypot accept error on port 9999: %v", err)
					continue
				}
				// Debug: Log when connection is accepted on fallback port
				remoteAddr := conn.RemoteAddr()
				if remoteAddr != nil {
					logChan <- fmt.Sprintf("[DEBUG] Honeypot accepted connection on port 9999 (fallback) from %s", remoteAddr.String())
				}
				// XDP đã redirect từ fake port đến 9999
				go handleConnection(conn, 9999)
			}
		}(ln9999)
	}

	if len(listeners) == 0 {
		logChan <- "[ERROR] Failed to bind any ports"
		logChan <- "[ERROR] Please check if ports are available or run with sudo for ports < 1024"
		return
	}

	// Check if port 9999 is bound (critical for XDP redirect)
	port9999Bound := false
	for _, port := range boundPorts {
		if port == 9999 {
			port9999Bound = true
			break
		}
	}
	if !port9999Bound {
		// Check if port 9999 is in listeners (fallback)
		for _, ln := range listeners {
			addr := ln.Addr()
			if addr != nil {
				addrStr := addr.String()
				if strings.Contains(addrStr, ":9999") {
					port9999Bound = true
					break
				}
			}
		}
	}

	if !port9999Bound {
		logChan <- "[WARN] Port 9999 is NOT bound - XDP redirect will fail!"
		logChan <- "[WARN] Please free port 9999: sudo lsof -i :9999 && sudo kill -9 <PID>"
		logChan <- "[WARN] Or change HONEYPOT_PORT in bpf/phantom.c and rebuild"
	}

	logChan <- fmt.Sprintf("[SYSTEM] Honeypot bound to %d ports (%d direct, 1 fallback) - The Mirage active", len(listeners), len(boundPorts))
	logChan <- "[SYSTEM] ✅ Honeypot is now ACCEPTING connections on port 9999"
	logChan <- "[SYSTEM] ✅ Ready to receive traffic from external hosts (192.168.1.21, etc.)"

	// Cleanup on exit
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	wg.Wait()
}

func getRandomBanner(serviceType string) string {
	switch serviceType {
	case "ssh":
		return sshBanners[rand.Intn(len(sshBanners))]
	case "http":
		return httpBanners[rand.Intn(len(httpBanners))]
	case "mysql":
		return mysqlBanners[rand.Intn(len(mysqlBanners))]
	case "redis":
		return redisBanners[rand.Intn(len(redisBanners))]
	case "ftp":
		return ftpBanners[rand.Intn(len(ftpBanners))]
	case "telnet":
		return telnetBanners[rand.Intn(len(telnetBanners))]
	default:
		return sshBanners[rand.Intn(len(sshBanners))]
	}
}

func selectRandomService() string {
	return serviceTypes[rand.Intn(len(serviceTypes))]
}

// selectServiceByPort: Chọn service type dựa trên port để tạo ảo giác thực tế hơn
// "The Mirage": Mỗi port sẽ có service type phù hợp, tạo "Ghost Grid" chân thực
func selectServiceByPort(port int) string {
	switch port {
	case 80, 443, 8080, 8443, 8000, 8888:
		return "http"
	case 3306, 5432, 1433, 1521:
		return "mysql"
	case 6379, 11211:
		return "redis"
	case 27017, 27018:
		return "mysql" // MongoDB handshake tương tự MySQL
	case 21:
		return "ftp"
	case 23:
		return "telnet"
	case 3389, 5900:
		return "ssh" // RDP/VNC giả lập như SSH
	case 9200, 5601:
		return "http" // Elasticsearch/Kibana giả lập như HTTP
	case 3000, 5000:
		return "http" // Node.js/Flask giả lập như HTTP
	default:
		// Random cho các port khác
		return selectRandomService()
	}
}

func handleConnection(conn net.Conn, originalPort int) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()
	if remoteAddr == nil {
		return
	}
	remote := remoteAddr.String()
	// Extract IP address only (remove port)
	// Handle IPv6 addresses with brackets: [::1]:9999 -> [::1]
	// Handle IPv4 addresses: 192.168.1.100:12345 -> 192.168.1.100
	var ip string
	if strings.HasPrefix(remote, "[") {
		// IPv6 with brackets: [::1]:9999
		endBracket := strings.Index(remote, "]")
		if endBracket > 0 {
			ip = remote[1:endBracket] // Remove brackets
		} else {
			// Fallback to simple split if bracket format is wrong
			ip = strings.Split(remote, ":")[0]
		}
	} else {
		// IPv4: 192.168.1.100:12345
		ip = strings.Split(remote, ":")[0]
	}
	t := time.Now().Format("15:04:05")

	// Chọn service type dựa trên port (để tạo ảo giác thực tế hơn)
	// Nếu originalPort là 9999, có nghĩa là XDP đã redirect từ fake port
	// Sử dụng random service để tạo "Ghost Grid" effect
	var serviceType string
	if originalPort == 9999 {
		// XDP đã redirect, không biết port gốc, sử dụng random
		serviceType = selectRandomService()
	} else {
		// Bind trực tiếp, biết port gốc
		serviceType = selectServiceByPort(originalPort)
	}
	banner := getRandomBanner(serviceType)

	logChan <- fmt.Sprintf("[%s] TRAP HIT! IP: %s | Port: %d | Service: %s", t, ip, originalPort, strings.ToUpper(serviceType))
	logAttack(ip, fmt.Sprintf("TRAP_HIT_PORT_%d", originalPort))

	if _, err := conn.Write([]byte(banner)); err != nil {
		logChan <- fmt.Sprintf("[%s] Error sending banner to %s: %v", t, ip, err)
		return
	}

	// The Mirage: Mỗi kết nối nhận một dịch vụ ngẫu nhiên
	// Tạo "Ghost Grid" - hacker thấy hàng ngàn cổng "mở" với các dịch vụ khác nhau
	switch serviceType {
	case "ssh":
		handleSSHInteraction(conn, remote, t)
	case "http":
		handleHTTPInteraction(conn, remote, t)
	case "telnet":
		handleTelnetInteraction(conn, remote, t)
	case "mysql":
		handleMySQLInteraction(conn, remote, t)
	case "redis":
		handleRedisInteraction(conn, remote, t)
	case "ftp":
		handleFTPInteraction(conn, remote, t)
	default:
		handleSSHInteraction(conn, remote, t)
	}
}

func handleSSHInteraction(conn net.Conn, remote, t string) {
	// Simulate SSH handshake delay
	time.Sleep(100 * time.Millisecond)

	// Send SSH prompt
	prompt := "root@server:~# "
	conn.Write([]byte(prompt))

	ip := strings.Split(remote, ":")[0]
	currentDir := "/root"
	commandHistory := []string{}

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		input := strings.TrimSpace(string(buf[:n]))
		if len(input) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		// Log command
		logChan <- fmt.Sprintf("[%s] SSH COMMAND: %s", t, input)
		logAttack(ip, fmt.Sprintf("SSH: %s", input))
		commandHistory = append(commandHistory, input)

		// Parse command
		parts := strings.Fields(input)
		if len(parts) == 0 {
			conn.Write([]byte(prompt))
			continue
		}

		cmd := parts[0]
		args := parts[1:]

		// Handle commands
		switch cmd {
		case "exit", "logout":
			conn.Write([]byte("Connection closed.\r\n"))
			return
		case "ls":
			output := "total 24\r\ndrwxr-xr-x 2 root root 4096 Dec 15 10:23 .\r\n"
			output += "drwxr-xr-x 3 root root 4096 Dec 10 09:15 ..\r\n"
			output += "-rw-r--r-- 1 root root  220 Dec 10 09:15 .bash_logout\r\n"
			output += "-rw-r--r-- 1 root root 3771 Dec 10 09:15 .bashrc\r\n"
			output += "-rw-r--r-- 1 root root  807 Dec 10 09:15 .profile\r\n"
			output += "-rw-r--r-- 1 root root 1024 Dec 12 14:30 backup.tar.gz\r\n"
			output += "drwxr-xr-x 2 root root 4096 Dec 13 11:45 documents\r\n"
			conn.Write([]byte(output + prompt))
		case "pwd":
			conn.Write([]byte(currentDir + "\r\n" + prompt))
		case "whoami":
			conn.Write([]byte("root\r\n" + prompt))
		case "id":
			conn.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\r\n" + prompt))
		case "uname", "uname -a":
			conn.Write([]byte("Linux server 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:04 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n" + prompt))
		case "cat":
			if len(args) > 0 {
				filename := args[0]
				if filename == "/etc/passwd" || filename == "passwd" {
					conn.Write([]byte("root:x:0:0:root:/root:/bin/bash\r\n" + prompt))
				} else if filename == "/etc/shadow" || filename == "shadow" {
					conn.Write([]byte("cat: /etc/shadow: Permission denied\r\n" + prompt))
				} else {
					conn.Write([]byte(fmt.Sprintf("cat: %s: No such file or directory\r\n", filename) + prompt))
				}
			} else {
				conn.Write([]byte("cat: missing file operand\r\n" + prompt))
			}
		case "cd":
			if len(args) > 0 {
				dir := args[0]
				if dir == ".." {
					currentDir = "/"
				} else if dir == "/" || dir == "/root" {
					currentDir = dir
				} else {
					currentDir = currentDir + "/" + dir
				}
				prompt = fmt.Sprintf("root@server:%s# ", currentDir)
			}
			conn.Write([]byte(prompt))
		case "history":
			output := ""
			for i, cmd := range commandHistory {
				output += fmt.Sprintf(" %d  %s\r\n", i+1, cmd)
			}
			conn.Write([]byte(output + prompt))
		case "ps", "ps aux":
			output := "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
			output += "root         1  0.0  0.1  22536  3824 ?        Ss   Dec10   0:01 /sbin/init\r\n"
			output += "root       456  0.0  0.2  47864  8960 ?        Ss   Dec10   0:02 /usr/sbin/sshd\r\n"
			output += "root       789  0.0  0.1  23456  5120 ?        S    Dec10   0:00 /usr/sbin/apache2\r\n"
			conn.Write([]byte(output + prompt))
		case "netstat", "netstat -an":
			output := "Active Internet connections (servers and established)\r\n"
			output += "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
			output += "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
			output += "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
			conn.Write([]byte(output + prompt))
		case "ifconfig", "ip", "ip addr":
			output := "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\r\n"
			output += "    inet 127.0.0.1/8 scope host lo\r\n"
			output += "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP\r\n"
			output += "    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0\r\n"
			conn.Write([]byte(output + prompt))
		case "wget", "curl":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("Connecting to %s...\r\n", args[0])))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
				conn.Write([]byte("Length: 1024 (1.0K) [text/html]\r\n"))
				conn.Write([]byte("Saving to: 'index.html'\r\n"))
				conn.Write([]byte("100%[======================================>] 1,024      --.-K/s   in 0s\r\n"))
				conn.Write([]byte("'index.html' saved [1024/1024]\r\n" + prompt))
			} else {
				conn.Write([]byte(fmt.Sprintf("%s: missing URL\r\n", cmd) + prompt))
			}
		default:
			// Simulate command execution delay
			time.Sleep(50 * time.Millisecond)
			conn.Write([]byte(fmt.Sprintf("bash: %s: command not found\r\n", cmd) + prompt))
		}
	}
}

func handleHTTPInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	ip := strings.Split(remote, ":")[0]

	// Parse HTTP request
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return
	}

	requestLine := lines[0]
	logChan <- fmt.Sprintf("[%s] HTTP REQUEST: %s", t, requestLine)
	logAttack(ip, fmt.Sprintf("HTTP: %s", requestLine))

	// Extract method and path
	parts := strings.Fields(requestLine)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	path := parts[1]

	// Generate response based on path
	var response string

	switch path {
	case "/", "/index.html", "/index.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "Content-Length: 1024\r\n"
		response += "Connection: keep-alive\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Welcome</title></head>"
		response += "<body><h1>Welcome to Server</h1><p>System is running normally.</p>"
		response += "<a href='/admin'>Admin Panel</a> | <a href='/login'>Login</a></body></html>"
	case "/admin", "/admin.php", "/admin.html":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Admin Panel</title></head>"
		response += "<body><h1>Administration Panel</h1>"
		response += "<form method='POST' action='/admin/login'>"
		response += "<input type='text' name='username' placeholder='Username'><br>"
		response += "<input type='password' name='password' placeholder='Password'><br>"
		response += "<button type='submit'>Login</button></form></body></html>"
	case "/login", "/login.php":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Server: Apache/2.4.41 (Debian)\r\n"
		response += "Content-Type: text/html; charset=UTF-8\r\n"
		response += "\r\n"
		response += "<!DOCTYPE html><html><head><title>Login</title></head>"
		response += "<body><h1>User Login</h1>"
		response += "<form method='POST' action='/login/check'>"
		response += "<input type='text' name='user' placeholder='Username'><br>"
		response += "<input type='password' name='pass' placeholder='Password'><br>"
		response += "<button type='submit'>Sign In</button></form></body></html>"
	case "/api", "/api/v1", "/api/users":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: application/json\r\n"
		response += "\r\n"
		response += `{"status":"ok","data":[{"id":1,"name":"admin"},{"id":2,"name":"user"}]}`
	case "/robots.txt":
		response = "HTTP/1.1 200 OK\r\n"
		response += "Content-Type: text/plain\r\n"
		response += "\r\n"
		response += "User-agent: *\nDisallow: /admin/\nDisallow: /private/"
	case "/.git", "/.git/config":
		response = "HTTP/1.1 403 Forbidden\r\n"
		response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
		response += "\r\n"
		response += "403 Forbidden"
	default:
		// Check if it's a POST request with credentials
		if method == "POST" && strings.Contains(request, "password") {
			logChan <- fmt.Sprintf("[%s] HTTP POST with credentials detected!", t)
			response = "HTTP/1.1 302 Found\r\n"
			response += "Location: /admin/dashboard\r\n"
			response += "\r\n"
		} else {
			response = "HTTP/1.1 404 Not Found\r\n"
			response += "Server: nginx/1.18.0 (Ubuntu)\r\n"
			response += "Content-Type: text/html\r\n"
			response += "\r\n"
			response += "<h1>404 Not Found</h1><p>The requested URL was not found on this server.</p>"
		}
	}

	conn.Write([]byte(response))

	// Keep connection alive for a short time to allow multiple requests
	time.Sleep(100 * time.Millisecond)
}

func handleTelnetInteraction(conn net.Conn, remote, t string) {
	// Send login prompt
	conn.Write([]byte("\r\nUbuntu 20.04.3 LTS\r\n\r\n"))
	time.Sleep(200 * time.Millisecond)
	conn.Write([]byte("server login: "))

	buf := make([]byte, 1024)
	loginAttempts := 0

	// Wait for username
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	username := strings.TrimSpace(string(buf[:n]))
	logChan <- fmt.Sprintf("[%s] TELNET LOGIN ATTEMPT: username='%s'", t, username)

	conn.Write([]byte("\r\nPassword: "))

	// Wait for password (don't echo)
	n, err = conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	password := strings.TrimSpace(string(buf[:n]))
	loginAttempts++

	ip := strings.Split(remote, ":")[0]
	logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s (password length: %d)", t, loginAttempts, ip, len(password))
	logAttack(ip, fmt.Sprintf("TELNET_LOGIN: user=%s, pass=***", username))

	// Simulate login delay
	time.Sleep(500 * time.Millisecond)

	// Always fail login but show different messages
	if loginAttempts < 3 {
		conn.Write([]byte("\r\nLogin incorrect\r\n\r\n"))
		conn.Write([]byte("server login: "))
		// Wait for another attempt
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		username = strings.TrimSpace(string(buf[:n]))
		conn.Write([]byte("\r\nPassword: "))
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		loginAttempts++
		logChan <- fmt.Sprintf("[%s] TELNET PASSWORD ATTEMPT #%d from %s", t, loginAttempts, ip)
	}

	// After 3 attempts, show "connection closed"
	conn.Write([]byte("\r\nToo many login attempts. Connection closed.\r\n"))
}

func handleMySQLInteraction(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	logChan <- fmt.Sprintf("[%s] MySQL connection attempt from %s", t, ip)
	logAttack(ip, "MySQL_CONNECTION")

	// MySQL handshake has already been sent in banner
	// Wait for authentication packet
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// Parse authentication attempt
	// MySQL auth packet structure is complex, but we can detect username
	if n > 4 {
		usernameLen := int(buf[4])
		if usernameLen > 0 && usernameLen < 32 {
			username := string(buf[5 : 5+usernameLen])
			logChan <- fmt.Sprintf("[%s] MySQL LOGIN: username='%s'", t, username)
			logAttack(ip, fmt.Sprintf("MySQL_LOGIN: user=%s", username))
		}
	}

	// Send error response (authentication failed)
	errorPacket := []byte{0xff, 0x15, 0x04, 0x23, 0x28, 0x30, 0x30, 0x30, 0x30, 0x34}
	errorPacket = append(errorPacket, []byte("Access denied for user")...)
	conn.Write(errorPacket)

	time.Sleep(100 * time.Millisecond)
}

func handleRedisInteraction(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	logChan <- fmt.Sprintf("[%s] Redis connection from %s", t, ip)
	logAttack(ip, "REDIS_CONNECTION")

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		logChan <- fmt.Sprintf("[%s] REDIS COMMAND: %s", t, command)
		logAttack(ip, fmt.Sprintf("REDIS: %s", command))

		// Parse Redis protocol (simplified)
		parts := strings.Fields(command)
		if len(parts) == 0 {
			conn.Write([]byte("-ERR unknown command\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		switch cmd {
		case "PING":
			conn.Write([]byte("+PONG\r\n"))
		case "INFO":
			conn.Write([]byte("$100\r\n# Server\r\nredis_version:6.2.6\r\nredis_mode:standalone\r\nos:Linux 5.4.0 x86_64\r\n"))
		case "GET":
			if len(args) > 0 {
				conn.Write([]byte("$-1\r\n")) // NULL
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'get' command\r\n"))
			}
		case "SET":
			if len(args) >= 2 {
				conn.Write([]byte("+OK\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'set' command\r\n"))
			}
		case "KEYS":
			conn.Write([]byte("*0\r\n")) // Empty array
		case "AUTH":
			if len(args) > 0 {
				logChan <- fmt.Sprintf("[%s] REDIS AUTH attempt with password", t)
				conn.Write([]byte("-ERR invalid password\r\n"))
			} else {
				conn.Write([]byte("-ERR wrong number of arguments for 'auth' command\r\n"))
			}
		case "QUIT", "EXIT":
			conn.Write([]byte("+OK\r\n"))
			return
		default:
			conn.Write([]byte(fmt.Sprintf("-ERR unknown command '%s'\r\n", cmd)))
		}
	}
}

func handleFTPInteraction(conn net.Conn, remote, t string) {
	ip := strings.Split(remote, ":")[0]
	logChan <- fmt.Sprintf("[%s] FTP connection from %s", t, ip)
	logAttack(ip, "FTP_CONNECTION")

	// FTP banner already sent
	conn.Write([]byte("220 Welcome to FTP Server\r\n"))

	buf := make([]byte, 1024)
	authenticated := false

	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}

		command := strings.TrimSpace(string(buf[:n]))
		logChan <- fmt.Sprintf("[%s] FTP COMMAND: %s", t, command)
		logAttack(ip, fmt.Sprintf("FTP: %s", command))

		parts := strings.Fields(command)
		if len(parts) == 0 {
			conn.Write([]byte("500 Syntax error\r\n"))
			continue
		}

		cmd := strings.ToUpper(parts[0])
		args := parts[1:]

		switch cmd {
		case "USER":
			if len(args) > 0 {
				username := args[0]
				logChan <- fmt.Sprintf("[%s] FTP USER: %s", t, username)
				conn.Write([]byte("331 Password required\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "PASS":
			if len(args) > 0 {
				password := args[0]
				logChan <- fmt.Sprintf("[%s] FTP PASS attempt (password length: %d)", t, len(password))
				logAttack(ip, fmt.Sprintf("FTP_LOGIN: pass=***"))
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("530 Login incorrect\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "SYST":
			conn.Write([]byte("215 UNIX Type: L8\r\n"))
		case "PWD":
			conn.Write([]byte("257 \"/\" is current directory\r\n"))
		case "LIST", "LS":
			if authenticated {
				conn.Write([]byte("150 Opening ASCII mode data connection\r\n"))
				time.Sleep(100 * time.Millisecond)
				conn.Write([]byte("226 Transfer complete\r\n"))
			} else {
				conn.Write([]byte("530 Please login with USER and PASS\r\n"))
			}
		case "CWD":
			if len(args) > 0 {
				conn.Write([]byte(fmt.Sprintf("250 CWD command successful: %s\r\n", args[0])))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "RETR", "GET":
			if len(args) > 0 {
				conn.Write([]byte("550 File not found\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "STOR", "PUT":
			if len(args) > 0 {
				conn.Write([]byte("553 Requested action not taken\r\n"))
			} else {
				conn.Write([]byte("501 Syntax error in parameters\r\n"))
			}
		case "QUIT", "BYE":
			conn.Write([]byte("221 Goodbye\r\n"))
			return
		case "HELP":
			conn.Write([]byte("214-The following commands are recognized:\r\n"))
			conn.Write([]byte(" USER PASS SYST PWD LIST CWD RETR STOR QUIT\r\n"))
			conn.Write([]byte("214 Help OK\r\n"))
		default:
			conn.Write([]byte("502 Command not implemented\r\n"))
		}
	}
}
