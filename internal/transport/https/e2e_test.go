package https

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// generateTestCert creates a self-signed TLS certificate for testing.
func generateTestCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"test.example.com", "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	return tlsCert, pool
}

func TestE2E_TLSKnockAndFraming(t *testing.T) {
	meshSecret := make([]byte, 32)
	rand.Read(meshSecret)

	clientPubKey := make([]byte, 32)
	rand.Read(clientPubKey)

	tlsCert, certPool := generateTestCert(t)

	// --- Server side ---
	serverValidator := NewKnockValidator(meshSecret, DefaultKnockWindow)
	serverValidator.AddKnownClient(clientPubKey)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()
	tlsLn := tls.NewListener(tcpLn, serverTLS)
	addr := tcpLn.Addr().String()

	var wg sync.WaitGroup
	var serverErr error
	var serverReceived []byte
	serverReady := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErr = err
			close(serverReady)
			return
		}
		defer conn.Close()

		// Read all available data (knock request + body together)
		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr = err
			close(serverReady)
			return
		}

		// Parse and validate knock
		req, err := parseHTTPRequest(buf[:n])
		if err != nil {
			serverErr = err
			close(serverReady)
			return
		}

		peerKey := serverValidator.Validate(req)
		if peerKey == nil {
			serverErr = io.ErrUnexpectedEOF
			close(serverReady)
			return
		}

		// Send knock success response
		response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"status\":\"ok\",\"tunnel\":true}"
		conn.Write([]byte(response))
		close(serverReady)

		// Transition to framed tunnel mode
		reader := NewFrameReader(conn)
		writer := NewFrameWriter(conn)

		// Read data frame from client
		frame, err := reader.ReadFrame()
		if err != nil {
			serverErr = err
			return
		}
		serverReceived = frame.Payload

		// Echo it back
		writer.WriteData(serverReceived)
	}()

	// --- Client side ---
	clientKnock := NewKnockGenerator(meshSecret, DefaultKnockWindow)
	knock := clientKnock.Generate(clientPubKey)

	clientTLS := &tls.Config{
		ServerName: "test.example.com",
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}

	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	defer tcpConn.Close()

	tlsConn := tls.Client(tcpConn, clientTLS)
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	// Verify TLS 1.3
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version: got 0x%04x, want TLS 1.3 (0x0304)", state.Version)
	}
	t.Logf("TLS 1.3 handshake OK, cipher suite: %s", tls.CipherSuiteName(state.CipherSuite))

	// Send knock (headers + body in single write to avoid fragmentation)
	knockReq := "POST " + knock.Path + " HTTP/1.1\r\nHost: test.example.com\r\n"
	for key, value := range knock.Headers {
		knockReq += key + ": " + value + "\r\n"
	}
	knockReq += "Content-Length: " + itoa(len(knock.Body)) + "\r\n\r\n" + string(knock.Body)
	tlsConn.Write([]byte(knockReq))

	// Read knock response
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read knock response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("200")) {
		t.Fatalf("knock failed: %s", buf[:n])
	}
	t.Log("Knock authentication: PASS")

	// Wait for server to process knock and be ready for frames
	<-serverReady

	// Transition to framed tunnel mode
	writer := NewFrameWriter(tlsConn)
	reader := NewFrameReader(tlsConn)

	testData := []byte("End-to-end encrypted and authenticated tunnel payload!")
	writer.WriteData(testData)

	// Read echo frame
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frame, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("read echo frame: %v", err)
	}
	readBuf := frame.Payload
	n = len(readBuf)

	wg.Wait()

	if serverErr != nil {
		t.Fatalf("server error: %v", serverErr)
	}

	t.Logf("  Sent:     %q", testData)
	t.Logf("  Server:   %q", serverReceived)
	t.Logf("  Echo:     %q", readBuf[:n])

	if string(serverReceived) != string(testData) {
		t.Fatalf("server got %q, want %q", serverReceived, testData)
	}
	if string(readBuf[:n]) != string(testData) {
		t.Fatalf("echo got %q, want %q", readBuf[:n], testData)
	}
	t.Log("Full e2e (TLS 1.3 + Knock + Framed tunnel + echo): PASS")
}

func TestE2E_CoverSiteForUnauthenticatedClient(t *testing.T) {
	meshSecret := make([]byte, 32)
	rand.Read(meshSecret)

	tlsCert, certPool := generateTestCert(t)

	// Setup server with knock validator (no known clients)
	serverValidator := NewKnockValidator(meshSecret, DefaultKnockWindow)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer tcpLn.Close()
	tlsLn := tls.NewListener(tcpLn, serverTLS)
	addr := tcpLn.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := tlsLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		req, _ := parseHTTPRequest(buf[:n])
		peerKey := serverValidator.Validate(req)

		if peerKey == nil {
			// Serve cover site — this is what a probe or regular browser sees
			cover := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body>Welcome to our site!</body></html>"
			conn.Write([]byte(cover))
		}
	}()

	// Client connects as a normal browser (no knock)
	clientTLS := &tls.Config{
		ServerName: "test.example.com",
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}

	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tcpConn.Close()

	tlsConn := tls.Client(tcpConn, clientTLS)
	tlsConn.HandshakeContext(context.Background())

	// Send a normal GET request
	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: test.example.com\r\n\r\n"))

	buf := make([]byte, 4096)
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	response := string(buf[:n])
	if !bytes.Contains(buf[:n], []byte("200 OK")) {
		t.Fatalf("expected 200 OK, got: %s", response)
	}
	if !bytes.Contains(buf[:n], []byte("Welcome")) {
		t.Fatalf("expected cover site content, got: %s", response)
	}

	wg.Wait()
	t.Log("Unauthenticated client sees cover site: PASS")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
