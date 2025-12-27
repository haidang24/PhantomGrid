#!/bin/bash
# Test fake ports visibility

echo "=== Testing Fake Ports Visibility ==="
echo ""

SERVER_IP="${1:-192.168.174.163}"

echo "Server IP: $SERVER_IP"
echo ""

echo "From Kali, run:"
echo "  nmap -p 80,443,3306,8080,9999 $SERVER_IP"
echo ""

echo "Expected results:"
echo "  - Port 80: open (if honeypot binded)"
echo "  - Port 443: open (if honeypot binded)"
echo "  - Port 3306: open (if honeypot binded)"
echo "  - Port 8080: open (if honeypot binded)"
echo "  - Port 9999: open (honeypot fallback)"
echo ""

echo "If only port 9999 shows:"
echo "  → Packets to fake ports may be dropped"
echo "  → Check XDP logic: fake ports should be PASS before stealth scan"
echo "  → Check mutate_os_personality: should not modify fake ports"
echo ""

echo "Debug on server:"
echo "  sudo tcpdump -i ens33 -n 'tcp port 80 or tcp port 443' -v"
echo ""

echo "Check honeypot logs in dashboard:"
echo "  - Look for '[DEBUG] Honeypot accepted connection on port 80'"
echo "  - Look for '[TRAP HIT]' messages"
echo ""

