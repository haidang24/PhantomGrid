#!/bin/bash
# Test script to debug Kali connection issue

echo "=== Testing Kali Connection Issue ==="
echo ""

SERVER_IP="${1:-192.168.174.163}"

echo "Server IP: $SERVER_IP"
echo ""

# Test 1: Check if port 9999 is listening on all interfaces
echo "1. Checking port 9999 binding..."
if netstat -tlnp 2>/dev/null | grep -q ":9999" || ss -tlnp 2>/dev/null | grep -q ":9999"; then
    echo "   ✅ Port 9999 is listening"
    netstat -tlnp 2>/dev/null | grep ":9999" || ss -tlnp 2>/dev/null | grep ":9999"
    
    # Check if binding to 0.0.0.0 (all interfaces)
    if netstat -tlnp 2>/dev/null | grep ":9999" | grep -q "0.0.0.0" || ss -tlnp 2>/dev/null | grep ":9999" | grep -q "0.0.0.0"; then
        echo "   ✅ Binding to 0.0.0.0 (all interfaces) - OK"
    else
        echo "   ⚠️  May be binding to 127.0.0.1 only"
    fi
else
    echo "   ❌ Port 9999 is NOT listening"
    exit 1
fi

# Test 2: Check XDP attachment
echo ""
echo "2. Checking XDP attachment..."
XDP_MODE=$(ip link show ens33 2>/dev/null | grep -i xdp | grep -o "xdpgeneric\|xdp" | head -1)
if [ -n "$XDP_MODE" ]; then
    echo "   ✅ XDP is attached (mode: $XDP_MODE)"
    ip link show ens33 | grep -i xdp
else
    echo "   ❌ XDP is NOT attached"
fi

# Test 3: Check firewall
echo ""
echo "3. Checking firewall rules..."
if command -v iptables &> /dev/null; then
    BLOCKING_RULES=$(sudo iptables -L INPUT -n -v 2>/dev/null | grep -c "DROP\|REJECT" || echo "0")
    if [ "$BLOCKING_RULES" -gt 0 ]; then
        echo "   ⚠️  Found blocking firewall rules:"
        sudo iptables -L INPUT -n -v 2>/dev/null | grep -E "DROP|REJECT" | head -5
    else
        echo "   ✅ No blocking firewall rules found"
    fi
    
    # Check specific rule for port 9999
    PORT_9999_RULE=$(sudo iptables -L INPUT -n -v 2>/dev/null | grep "9999" | head -1)
    if [ -n "$PORT_9999_RULE" ]; then
        echo "   Port 9999 rule: $PORT_9999_RULE"
    fi
fi

# Test 4: Test local connection
echo ""
echo "4. Testing LOCAL connection..."
if timeout 2 bash -c "echo 'test' | nc -w 1 localhost 9999" 2>/dev/null; then
    echo "   ✅ Local connection works"
else
    echo "   ❌ Local connection failed"
fi

# Test 5: Test from server's own IP
echo ""
echo "5. Testing from server's own IP ($SERVER_IP)..."
if timeout 2 bash -c "echo 'test' | nc -w 1 $SERVER_IP 9999" 2>/dev/null; then
    echo "   ✅ Connection from $SERVER_IP works"
else
    echo "   ❌ Connection from $SERVER_IP failed"
    echo "   This suggests XDP may be blocking or checksum issue"
fi

# Test 6: Instructions for Kali test
echo ""
echo "=== Instructions for Kali Test ==="
echo ""
echo "From Kali machine, run:"
echo "  nc -v $SERVER_IP 9999"
echo ""
echo "Expected results:"
echo "  - Connection successful → Honeypot banner"
echo "  - Connection timeout → XDP drop or firewall"
echo "  - Connection refused → Honeypot not listening"
echo ""
echo "If connection timeout, check:"
echo "  1. XDP statistics: sudo bpftool map dump name attack_stats"
echo "  2. Capture packets: sudo tcpdump -i ens33 -n 'tcp port 9999' -v"
echo "  3. Honeypot logs in dashboard: [TRAP HIT] messages"

