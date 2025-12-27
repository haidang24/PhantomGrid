#!/bin/bash
# Test script to verify honeypot connectivity

echo "=== Testing Honeypot Connectivity ==="
echo ""

SERVER_IP="${1:-192.168.174.163}"

echo "Testing connection to $SERVER_IP:9999..."
echo ""

# Test 1: Direct connection
echo "1. Testing direct connection to port 9999..."
if timeout 3 bash -c "echo 'test' | nc -w 2 $SERVER_IP 9999" 2>/dev/null; then
    echo "   ✅ Connection successful"
else
    echo "   ❌ Connection failed"
fi

# Test 2: Test port 80 (should be redirected)
echo ""
echo "2. Testing connection to port 80 (should redirect to 9999)..."
if timeout 3 bash -c "echo 'GET / HTTP/1.0' | nc -w 2 $SERVER_IP 80" 2>/dev/null; then
    echo "   ✅ Connection successful (redirected)"
else
    echo "   ❌ Connection failed"
fi

# Test 3: Check if we get response
echo ""
echo "3. Testing with telnet..."
timeout 2 telnet $SERVER_IP 9999 2>&1 | head -5

echo ""
echo "=== Test Complete ==="
echo ""
echo "If connections fail, check:"
echo "  - XDP is attached: ip link show ens33 | grep xdp"
echo "  - Honeypot listening: sudo netstat -tlnp | grep 9999"
echo "  - Firewall rules: sudo iptables -L -n -v"

