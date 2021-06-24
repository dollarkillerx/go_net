package go_net

import (
	"net"
	"testing"
)

func TestUDPLib(t *testing.T) {
	socket := OpenSocket()
	query := DnsQuery(net.ParseIP("127.0.0.1"), 8080, net.ParseIP("223.5.5.5"))
	SendPacket(socket, query, net.ParseIP("223.5.5.5"))
}
