package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/elastic/go-elasticsearch/v8"
	"github.com/emersion/go-smtp"
	"github.com/joho/godotenv"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/phires/go-guerrilla/backends"
)

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func printMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

var (
	SPFFail = &smtp.SMTPError{
		Code:         550,
		Message:      "Sender not permitted: sender policy framework verification failed",
		EnhancedCode: smtp.EnhancedCode{5, 7, 1},
	}
	SPFTempError = &smtp.SMTPError{
		Code:         451,
		Message:      "Temporary failure: unable to validate sender policy framework record",
		EnhancedCode: smtp.EnhancedCode{4, 4, 3},
	}
	SPFPermError = &smtp.SMTPError{
		Code:         550,
		Message:      "Sender not permitted: unable to interpret sender policy framework record",
		EnhancedCode: smtp.EnhancedCode{5, 5, 2},
	}
)

// The Backend implements SMTP server methods.
type Backend struct {
	minioClient *minio.Client // Declare minioClient as a global variable
	esClient    *elasticsearch.Client
}

// A Session is returned after successful login.
type Session struct {
	startedAt     time.Time
	minioClient   *minio.Client
	esClient      *elasticsearch.Client
	bodySize      int64
	from          string
	tos           []string
	helo          string
	heloDNS       []string
	remoteip      net.IP
	spf           int
	spfresult     string
	id            string
	requireTLS    bool
	rdns          []string
	spfDuration   time.Duration
	storeAt       time.Time
	storeDuration time.Duration
	tls           *tls.ConnectionState
	header        textproto.MIMEHeader
	values        map[string]interface{}
	subject       string
}

func (s *Session) createId() {
	h := sha256.New()
	h.Write([]byte(s.remoteip.String()))
	h.Write([]byte(s.helo))
	h.Write([]byte(time.Now().String()))
	s.id = fmt.Sprintf("%x", h.Sum(nil))
}

func (s *Session) checkRDNS() {
	names, err := net.LookupAddr(s.remoteip.String())
	if err != nil {
		log.Println(s.id, "Error looking up RDNS:", err)
	} else {
		s.rdns = names
		log.Println(s.id, "RDNS resolved:", s.remoteip, names)
	}
	ips, err := net.LookupHost(s.helo)
	if err != nil {
		log.Println(s.id, "Error looking up HELO:", err)
	} else {
		s.heloDNS = ips
		log.Println(s.id, "HELO resolved:", s.helo, ips)
	}
}

func (s *Session) checkSPF(from string) {
	spfAt := time.Now()
	// validate sender
	result, err := spf.CheckHostWithSender(s.remoteip, s.helo, from)
	if result == spf.Fail {
		log.Println(s.id, "SPF fail:", s.remoteip, s.helo, from, err)
		s.spfresult = "fail"
		s.spf = 3
	} else if result == spf.TempError {
		log.Println(s.id, "SPF temperror:", s.remoteip, s.helo, from, err)
		s.spfresult = "temperror"
		s.spf = 2
	} else if result == spf.PermError {
		log.Println(s.id, "SPF permerror:", s.remoteip, s.helo, from, err)
		s.spfresult = "permerror"
		s.spf = 3
	} else if result == spf.SoftFail {
		log.Println(s.id, "SPF softfail:", s.remoteip, s.helo, from, err)
		s.spf = 2
		s.spfresult = "softfail"
	} else if result == spf.Neutral || result == spf.None {
		log.Println(s.id, "SPF neutral:", s.remoteip, s.helo, from, err)
		s.spf = 0
		s.spfresult = "neutral"
	} else if result == spf.Pass {
		log.Println(s.id, "SPF pass", s.remoteip.String(), s.helo, from)
		s.spf = 1
		s.spfresult = "pass"
	}
	s.spfDuration = time.Since(spfAt)
}

// NewSession is called after client greeting (EHLO, HELO).
func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	log.Println("New session from:", c.Conn().RemoteAddr(), "host:", c.Hostname(), c.Conn().RemoteAddr())
	ip, _, _ := net.SplitHostPort(c.Conn().RemoteAddr().String())
	tls, _ := c.TLSConnectionState()
	return &Session{
		header:      nil,
		startedAt:   time.Now(),
		minioClient: bkd.minioClient, // Pass the minioClient to the session
		esClient:    bkd.esClient,
		tos:         []string{},
		values:      make(map[string]interface{}),
		remoteip:    net.ParseIP(ip),
		helo:        c.Hostname(),
		tls:         &tls,
	}, nil
}

// AuthMechanisms returns a slice of available auth mechanisms; only PLAIN is
// supported in this example.
func (s *Session) AuthMechanisms() []string {
	return nil
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// set from address
	s.from = from
	// create and set message id
	s.createId()
	// read size from opts
	if opts.Size > 0 {
		s.bodySize = opts.Size
	}
	if opts.RequireTLS {
		s.requireTLS = true
	}
	// check reverse dns
	s.checkRDNS()
	// check spf
	s.checkSPF(from)
	printMemUsage()
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// TODO: validate recipient
	s.tos = append(s.tos, to)
	return nil
}

func (s *Session) Data(r io.Reader) error {

	rec := strings.NewReader(
		fmt.Sprintf("Received: from %s (%s) by %s\n", s.helo, s.remoteip, os.Getenv("MAIL_HOSTNAME")) +
			fmt.Sprintf("  with ESMTP id %s\n", s.id) +
			fmt.Sprintf("  for <%s>; %s\n", s.tos[0], time.Now().Format(time.RFC1123Z)))

	multiReader := io.MultiReader(rec, r)
	var buf bytes.Buffer
	data := io.TeeReader(multiReader, &buf)
	printMemUsage()

	// Upload the email data to MinIO using a streaming reader
	s.storeAt = time.Now()
	res, rerr := s.minioClient.PutObject(
		context.Background(),
		os.Getenv("S3_BUCKET_NAME"),
		s.id,
		data,
		-1,
		minio.PutObjectOptions{
			ContentType: "message/rfc822",
			PartSize:    5 * 1024 * 1024,
		})
	s.storeDuration = time.Since(s.storeAt)
	if rerr != nil || res.Location == "" {
		log.Println(s.id, "Error uploading email data to MinIO:", rerr)
		return &smtp.SMTPError{
			Code:         451,
			Message:      "Temporary backend failure, please try again later",
			EnhancedCode: smtp.EnhancedCode{4, 4, 0},
		}
	} else {
		log.Println("Stored in", s.storeDuration, "key:", s.id, "url:", res.Location, res)
	}

	printMemUsage()

	headerReader := textproto.NewReader(bufio.NewReader(&buf))
	var err error
	s.header, err = headerReader.ReadMIMEHeader()
	if err == nil || err == io.EOF {
		// decode the subject
		if subject, ok := s.header["Subject"]; ok {
			s.subject = subject[0]
			log.Println(s.id, "Subject:", s.subject)
		}
		if from, ok := s.header["From"]; ok {
			s.from = from[0]
			log.Println(s.id, "From:", s.from)
		}
	} else {
		log.Println(s.id, "Error processing headers:", err)
	}

	printMemUsage()

	type Envelope struct {
		MailFrom      string        `json:"mail_from"`
		RcptTo        []string      `json:"rcpt_to"`
		Helo          string        `json:"helo"`
		HeloDNS       []string      `json:"helo_dns"`
		RemoteIp      string        `json:"remote_ip"`
		RDNS          []string      `json:"rdns"`
		Spf           int           `json:"spf"`
		SpfIn         time.Duration `json:"spf_in"`
		SpfResult     string        `json:"spf_result"`
		TLS           bool          `json:"tls"`
		TLSVersion    string        `json:"tls_version"`
		TLSCipher     string        `json:"tls_cipher"`
		TLSRequired   bool          `json:"tls_required"`
		TLSServerName string        `json:"tls_server_name"`
		QueuedId      string        `json:"queued_id"`
	}
	type Document struct {
		Endpoint  string              `json:"endpoint"` // hostname
		Envelope  Envelope            `json:"envelope"`
		Headers   map[string][]string `json:"headers"`
		StoredUrl string              `json:"stored_url"`
		StoredIn  time.Duration       `json:"stored_in"`
		Date      time.Time           `json:"date"`
	}

	document := Document{}
	document.Envelope.MailFrom = s.from
	document.Envelope.RcptTo = s.tos
	document.Envelope.Helo = s.helo
	document.Envelope.HeloDNS = s.heloDNS
	document.Envelope.RemoteIp = s.remoteip.String()
	document.Envelope.RDNS = s.rdns
	document.Envelope.Spf = s.spf
	document.Envelope.SpfIn = s.spfDuration
	document.Envelope.SpfResult = s.spfresult
	document.Envelope.TLS = s.tls.HandshakeComplete
	if s.tls.HandshakeComplete {
		document.Envelope.TLSVersion = tls.VersionName(s.tls.Version)
		document.Envelope.TLSCipher = tls.CipherSuiteName(s.tls.CipherSuite)
		document.Envelope.TLSServerName = s.tls.ServerName
	}
	document.Envelope.TLSRequired = s.requireTLS
	document.Envelope.QueuedId = s.id

	document.Endpoint = os.Getenv("MAIL_HOSTNAME")
	document.StoredUrl = res.Location
	document.StoredIn = s.storeDuration
	document.Date = time.Now()
	document.Headers = make(map[string][]string)

	interestingHeaders := []string{
		"From",
		"To",
		"Subject",
		"Date",
		"Message-ID",
		"Message-Id",
		"X-Mailer",
		"In-Reply-To",
		"DKIM-Signature",
		"Mime-Version",
		"Content-Type",
	}

	for _, header := range interestingHeaders {
		if s.header[header] != nil && len(s.header[header]) > 0 {
			document.Headers[header] = s.header[header]
		}
	}

	esdata, _ := json.Marshal(document)
	es, err := s.esClient.Index("messages", bytes.NewReader(esdata))
	if es.IsError() {
		log.Println(s.id, "Error indexing:", err, es)
	} else {
		log.Println(s.id, "Indexed document:", es)
	}

	// Return response
	printMemUsage()
	if s.spf > 2 {
		return SPFFail
	}

	if s.requireTLS && s.tls == nil {
		return &smtp.SMTPError{
			Code:         530,
			Message:      "Must issue a STARTTLS command first",
			EnhancedCode: smtp.EnhancedCode{5, 7, 0},
		}
	}

	return nil
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	printMemUsage()
	duration := time.Since(s.startedAt)
	log.Println(s.id, "Session duration:", duration)
	return nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// Create a new MinIO client
	minioClient, err := minio.New(os.Getenv("S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("S3_ACCESS_KEY"), os.Getenv("S3_SECRET_KEY"), ""),
		Secure: false,
	})
	if err != nil {
		log.Fatal(err)
	}

	esCfg := elasticsearch.Config{
		Addresses: []string{os.Getenv("ES_URL")},
		APIKey:    os.Getenv("ES_API_KEY"),
	}

	esClient, err := elasticsearch.NewClient(esCfg)
	if err != nil {
		backends.Log().WithError(err).Error(err, " Unable to connect to Elasticsearch: ", esClient)
	}

	be := &Backend{
		minioClient: minioClient,
		esClient:    esClient,
	}

	s := smtp.NewServer(be)

	s.Network = "tcp"
	s.Addr = ":2525"
	s.Domain = os.Getenv("MAIL_HOSTNAME")
	s.WriteTimeout = 20 * time.Second
	s.ReadTimeout = 20 * time.Second
	s.MaxMessageBytes, _ = strconv.ParseInt(os.Getenv("MAX_MESSAGE_BYTES"), 10, 64)
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true
	s.LMTP = false
	s.EnableSMTPUTF8 = false
	s.EnableREQUIRETLS = true
	s.EnableBINARYMIME = false

	c, err := tls.LoadX509KeyPair(os.Getenv("SSL_CERT"), os.Getenv("SSL_KEY"))
	if err != nil {
		log.Fatal(err)
	}
	s.TLSConfig = &tls.Config{Certificates: []tls.Certificate{c}}

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
	printMemUsage()
}
