package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		// Print detailed hex dump of received packet
		fmt.Printf("\nReceived DNS packet from %s (%d bytes):\n", source, size)
		fmt.Printf("Hex dump of received data:\n%s\n", hex.Dump(buf[:size]))

		// Parse the query and create response
		response := createResponse(buf[:size])

		// Print response we're sending back
		fmt.Printf("\nSending response (%d bytes):\n", len(response))
		fmt.Printf("Hex dump of response:\n%s\n", hex.Dump(response))

		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}

func createResponse(query []byte) []byte {
	// Calculate total response size: 8 (header) + domain name size + 4 (QTYPE + QCLASS)
	// For localdns.io: 8 (header) + 15 (domain name with length bytes) + 4 = 27 bytes
	response := make([]byte, len(query))

	// 1. Copy first 8 bytes (header) from query
	copy(response, query)

	// // 2. Set the ID to 1234 (0x04D2 in hex)
	// response[0] = 0x04
	// response[1] = 0xD2

	// 3. Set QR bit to 1 (response)
	response[2] = response[2] | 0b10000000

	// 4. Set QDCOUNT to 1 (we're including one question)
	response[4] = 0x00
	response[5] = 0x01

	// 5. Add the question section starting at byte 12
	offset := 12

	// Add "localdns" label
	response[offset] = 0x0c
	copy(response[offset+1:offset+13], []byte("localdns"))
	offset += 13

	// Add "io" label
	response[offset] = 0x02                         // length of "io"
	copy(response[offset+1:offset+3], []byte("io")) // the string "io"
	offset += 3

	// Add null byte to terminate domain name
	response[offset] = 0x00
	offset++

	// Add QTYPE (1 for A record)
	response[offset] = 0x00
	response[offset+1] = 0x01
	offset += 2

	// Add QCLASS (1 for IN)
	response[offset] = 0x00
	response[offset+1] = 0x01

	return response
}

// ParseDomainName reads a domain name from a DNS packet
// The offset is where to start reading in the packet
// Returns the domain name and the number of bytes read
func parseDomainName(packet []byte, offset int) (string, int, error) {
	if offset >= len(packet) {
		return "", 0, errors.New("offset beyond packet length")
	}

	// Position in the current packet
	pos := offset
	// Final domain name
	var domain string
	// Keep track of bytes read
	bytesRead := 0

	// Read until we hit a 0 length label or end of packet
	for {
		// Get the length of the next label
		if pos >= len(packet) {
			return "", 0, errors.New("incomplete domain name")
		}
		length := int(packet[pos])

		// If length is 0, we're done
		if length == 0 {
			bytesRead++
			break
		}

		// Move past length byte
		pos++
		bytesRead++

		// Check if we have enough bytes for this label
		if pos+length > len(packet) {
			return "", 0, errors.New("incomplete label")
		}

		// Add a dot if this isn't the first label
		if domain != "" {
			domain += "."
		}

		// Add the label to our domain
		domain += string(packet[pos : pos+length])

		// Move position to after this label
		pos += length
		bytesRead += length
	}

	return domain, bytesRead, nil
}

// parseQuestion parses a single question from a DNS packet
func parseQuestion(packet []byte, offset int) (domain string, qtype uint16, qclass uint16, bytesRead int, err error) {
	// Parse domain name
	domain, nameBytes, err := parseDomainName(packet, offset)
	if err != nil {
		return "", 0, 0, 0, err
	}
	bytesRead = nameBytes

	// Check if we have enough bytes for QTYPE and QCLASS (4 bytes total)
	if offset+bytesRead+4 > len(packet) {
		return "", 0, 0, 0, errors.New("packet too short for question section")
	}

	// Read QTYPE (2 bytes)
	qtype = uint16(packet[offset+bytesRead])<<8 | uint16(packet[offset+bytesRead+1])
	bytesRead += 2

	// Read QCLASS (2 bytes)
	qclass = uint16(packet[offset+bytesRead])<<8 | uint16(packet[offset+bytesRead+1])
	bytesRead += 2

	return domain, qtype, qclass, bytesRead, nil
}

// Example usage in your main DNS server:
func HandleDNSPacket(packet []byte) {
	if len(packet) < 12 {
		fmt.Println("Packet too short")
		return
	}

	// Parse header fields
	id := uint16(packet[0])<<8 | uint16(packet[1])
	flags := uint16(packet[2])<<8 | uint16(packet[3])
	qdcount := uint16(packet[4])<<8 | uint16(packet[5])

	fmt.Printf("DNS Query ID: %d\n", id)
	fmt.Printf("Flags: %016b\n", flags)
	fmt.Printf("Questions: %d\n", qdcount)

	// Parse questions
	offset := 12 // Start after header
	for i := 0; i < int(qdcount); i++ {
		domain, qtype, qclass, bytesRead, err := parseQuestion(packet, offset)
		if err != nil {
			fmt.Printf("Error parsing question: %v\n", err)
			return
		}

		fmt.Printf("Question %d:\n", i+1)
		fmt.Printf("  Domain: %s\n", domain)
		fmt.Printf("  Type: %d\n", qtype)
		fmt.Printf("  Class: %d\n", qclass)

		offset += bytesRead
	}
}
