#!/bin/bash
# Script to check and stop services on critical asset ports

echo "=== Checking services on critical asset ports ==="
echo ""

# Check SSH (port 22)
if sudo netstat -tlnp 2>/dev/null | grep -q ":22 " || sudo ss -tlnp 2>/dev/null | grep -q ":22 "; then
    echo "⚠️  SSH (port 22) is LISTENING"
    echo "   This is a critical asset port that should be hidden by XDP"
    echo "   However, localhost scans may still see it if service is running"
    echo ""
fi

# Check MySQL (port 3306)
if sudo netstat -tlnp 2>/dev/null | grep -q ":3306 " || sudo ss -tlnp 2>/dev/null | grep -q ":3306 "; then
    echo "⚠️  MySQL (port 3306) is LISTENING"
    echo "   This is a critical asset port that should be hidden by XDP"
    echo ""
fi

# Check PostgreSQL (port 5432)
if sudo netstat -tlnp 2>/dev/null | grep -q ":5432 " || sudo ss -tlnp 2>/dev/null | grep -q ":5432 "; then
    echo "⚠️  PostgreSQL (port 5432) is LISTENING"
    echo "   This is a critical asset port that should be hidden by XDP"
    echo ""
fi

# Check Redis (port 6379)
if sudo netstat -tlnp 2>/dev/null | grep -q ":6379 " || sudo ss -tlnp 2>/dev/null | grep -q ":6379 "; then
    echo "⚠️  Redis (port 6379) is LISTENING"
    echo "   This is a critical asset port that should be hidden by XDP"
    echo ""
fi

# Check MongoDB (port 27017)
if sudo netstat -tlnp 2>/dev/null | grep -q ":27017 " || sudo ss -tlnp 2>/dev/null | grep -q ":27017 "; then
    echo "⚠️  MongoDB (port 27017) is LISTENING"
    echo "   This is a critical asset port that should be hidden by XDP"
    echo ""
fi

echo "=== Explanation ==="
echo ""
echo "When scanning from localhost (127.0.0.1 or 192.168.174.163 → itself):"
echo "  - Traffic goes through LOOPBACK interface (lo)"
echo "  - XDP is attached to ens33 (external interface)"
echo "  - Therefore, localhost traffic does NOT go through XDP"
echo "  - Services on critical ports will still respond"
echo ""
echo "To test XDP protection:"
echo "  1. Scan from EXTERNAL machine (Kali VM, Windows, etc.)"
echo "  2. Or stop services on critical ports (not recommended for SSH)"
echo "  3. Or attach XDP to loopback (may cause issues)"
echo ""
echo "=== Current listening ports ==="
sudo netstat -tlnp 2>/dev/null | grep LISTEN | grep -E ":(22|3306|5432|6379|27017|8080|8443|9000) " || \
sudo ss -tlnp 2>/dev/null | grep LISTEN | grep -E ":(22|3306|5432|6379|27017|8080|8443|9000) "

