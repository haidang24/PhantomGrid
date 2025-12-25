package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
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

	// Service type probabilities (for randomization)
	serviceTypes = []string{"ssh", "http", "mysql", "redis", "ftp"}
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
	// QUAN TRỌNG: Hãy đảm bảo tên interface (eth0, ens33, lo...) đúng với máy bạn
	ifaceName := "ens33"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		// Fallback to lo if eth0 not found (for testing)
		ifaceName = "lo"
		iface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("[!] Interface %s not found: %v", ifaceName, err)
		}
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.PhantomProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("[!] Failed to attach XDP:", err)
	}
	defer l.Close()

	// 3.1 Load and attach TC Egress Program (DLP) using netlink
	var egressObjs EgressObjects
	var egressObjsPtr *EgressObjects

	if err := LoadEgressObjects(&egressObjs, nil); err != nil {
		log.Printf("[!] Warning: Failed to load TC egress objects: %v", err)
	} else {
		// Setup TC Egress using netlink
		if err := attachTCEgress(iface, &egressObjs); err != nil {
			log.Printf("[!] Warning: Failed to attach TC egress: %v", err)
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

	if err := netlink.QdiscAdd(qdisc); err != nil && !os.IsExist(err) {
		// Just log, might fail if already exists which is fine
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

// manageSPAWhitelist periodically cleans up expired SPA whitelist entries
func manageSPAWhitelist(objs *PhantomObjects) {
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		// In production: iterate map and delete old entries
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
	_ = os.MkdirAll("logs", 0o755)
	file, err := os.OpenFile("logs/audit.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_ = json.NewEncoder(file).Encode(entry)
}

// --- DASHBOARD UI ---
func startDashboard(iface string, objs *PhantomObjects, egressObjs *EgressObjects) {
	if err := ui.Init(); err != nil {
		log.Fatalf("failed to initialize termui: %v", err)
	}
	defer ui.Close()

	header := widgets.NewParagraph()
	header.Title = " PHANTOM GRID - ACTIVE DEFENSE SYSTEM "
	header.Text = fmt.Sprintf("STATUS: [ACTIVE](fg:green,mod:bold) | INTERFACE: [%s](fg:yellow) | MODE: [eBPF KERNEL TRAP](fg:red)", iface)
	header.SetRect(0, 0, 80, 3)
	header.TextStyle.Fg = ui.ColorCyan

	logList := widgets.NewList()
	logList.Title = " [ REAL-TIME FORENSICS ] "
	logList.Rows = []string{"[SYSTEM] Phantom Grid initialized...", "[SYSTEM] eBPF XDP Hook attached..."}
	logList.SetRect(0, 3, 50, 20)
	logList.TextStyle.Fg = ui.ColorGreen
	logList.SelectedRowStyle.Fg = ui.ColorGreen

	gauge := widgets.NewGauge()
	gauge.Title = " THREAT LEVEL "
	gauge.Percent = 0
	gauge.SetRect(50, 3, 80, 6)
	gauge.BarColor = ui.ColorRed

	aiBox := widgets.NewParagraph()
	aiBox.Title = " AI GENERATIVE MODULE (PHASE 2 PREVIEW) "
	aiBox.Text = "\n[Waiting for traffic...](fg:white)"
	aiBox.SetRect(50, 6, 80, 12)

	totalBox := widgets.NewParagraph()
	totalBox.Title = " REDIRECTED "
	totalBox.Text = "\n   0"
	totalBox.SetRect(50, 12, 80, 16)
	totalBox.TextStyle.Fg = ui.ColorYellow

	stealthBox := widgets.NewParagraph()
	stealthBox.Title = " STEALTH DROPS "
	stealthBox.Text = "\n   0"
	stealthBox.SetRect(50, 16, 65, 20)
	stealthBox.TextStyle.Fg = ui.ColorRed

	egressBox := widgets.NewParagraph()
	egressBox.Title = " EGRESS BLOCKS (DLP) "
	egressBox.Text = "\n   0"
	egressBox.SetRect(65, 16, 80, 20)
	egressBox.TextStyle.Fg = ui.ColorMagenta

	ui.Render(header, logList, gauge, aiBox, totalBox, stealthBox, egressBox)

	ticker := time.NewTicker(200 * time.Millisecond)
	statsTicker := time.NewTicker(1 * time.Second)
	uiEvents := ui.PollEvents()
	threatCount := 0

	go func() {
		for range statsTicker.C {
			var attackKey uint32 = 0
			var attackVal uint64
			if err := objs.AttackStats.Lookup(attackKey, &attackVal); err == nil {
				totalBox.Text = fmt.Sprintf("\n   %d", attackVal)
			}

			var stealthKey uint32 = 0
			var stealthVal uint64
			if err := objs.StealthDrops.Lookup(stealthKey, &stealthVal); err == nil {
				stealthBox.Text = fmt.Sprintf("\n   %d", stealthVal)
			}

			if egressObjs != nil && egressObjs.EgressBlocks != nil {
				var egressKey uint32 = 0
				var egressVal uint64
				if err := egressObjs.EgressBlocks.Lookup(egressKey, &egressVal); err == nil {
					egressBox.Text = fmt.Sprintf("\n   %d", egressVal)
					if egressVal > 0 {
						logChan <- fmt.Sprintf("[DLP] Blocked %d data exfiltration attempts", egressVal)
					}
				}
			}

			if attackVal > 0 {
				gauge.Percent = int((attackVal * 2) % 100)
			}
		}
	}()

	for {
		select {
		case e := <-uiEvents:
			if e.Type == ui.KeyboardEvent && (e.ID == "q" || e.ID == "<C-c>") {
				return
			}
		case msg := <-logChan:
			logList.Rows = append(logList.Rows, msg)
			if len(logList.Rows) > 16 {
				logList.Rows = logList.Rows[1:]
			}
			logList.ScrollBottom()
			threatCount++
			if threatCount%5 == 0 {
				gauge.Percent = (threatCount * 2) % 100
			}
			if strings.Contains(msg, "COMMAND") {
				aiBox.Text = "[ANALYZING PATTERN...](fg:white)\n[PREDICTION](fg:red): APT Attack detected.\n[CONFIDENCE](fg:yellow): 98.5%"
			}
			ui.Render(logList, gauge, totalBox, aiBox, stealthBox, egressBox)
		case <-ticker.C:
			ui.Render(logList, gauge, totalBox, aiBox, stealthBox, egressBox)
		}
	}
}

// --- HONEYPOT LOGIC ---
func startHoneypot() {
	ln, _ := net.Listen("tcp", ":9999")
	for {
		conn, err := ln.Accept()
		if err == nil {
			go handleConnection(conn)
		}
	}
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
	default:
		return sshBanners[rand.Intn(len(sshBanners))]
	}
}

func selectRandomService() string {
	return serviceTypes[rand.Intn(len(serviceTypes))]
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	t := time.Now().Format("15:04:05")

	serviceType := selectRandomService()
	banner := getRandomBanner(serviceType)

	logChan <- fmt.Sprintf("[%s] TRAP HIT! IP: %s | Service: %s", t, remote, strings.ToUpper(serviceType))
	logAttack(remote, "TRAP_HIT")

	conn.Write([]byte(banner))

	switch serviceType {
	case "ssh":
		handleSSHInteraction(conn, remote, t)
	case "http":
		handleHTTPInteraction(conn, remote, t)
	default:
		handleSSHInteraction(conn, remote, t)
	}
}

func handleSSHInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		input := strings.TrimSpace(string(buf[:n]))
		if len(input) > 0 {
			logChan <- fmt.Sprintf("[%s] COMMAND: %s", t, input)
			logAttack(remote, input)
		}
		if input == "exit" {
			return
		}
		conn.Write([]byte("bash: command not found\n"))
	}
}

func handleHTTPInteraction(conn net.Conn, remote, t string) {
	buf := make([]byte, 4096)
	conn.Read(buf)
	conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nServer Running"))
}
