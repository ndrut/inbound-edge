package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/joho/godotenv"
	"github.com/minio/minio-go"
)

// The Backend implements SMTP server methods.
type Backend struct {
	minioClient *minio.Client // Declare minioClient as a global variable
}

// NewSession is called after client greeting (EHLO, HELO).
func (bkd *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &Session{
		startTime:   time.Now(),
		minioClient: bkd.minioClient, // Pass the minioClient to the session
	}, nil
}

// A Session is returned after successful login.
type Session struct {
	startTime   time.Time
	minioClient *minio.Client // Declare minioClient as a session variable
}

// AuthMechanisms returns a slice of available auth mechanisms; only PLAIN is
// supported in this example.
func (s *Session) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *Session) Mail(from string, opts *smtp.MailOptions) error {
	// log.Println("Mail from:", from)
	return nil
}

func (s *Session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// log.Println("Rcpt to:", to)
	return nil
}

func (s *Session) Data(r io.Reader) error {
	// Generate a unique key for the S3 object
	key := fmt.Sprintf("email-%d", time.Now().UnixNano())

	// Upload the email data to MinIO using a streaming reader
	_, err := s.minioClient.PutObject("messages", key, r, -1, minio.PutObjectOptions{})
	if err != nil {
		return err
	}

	// log.Println("Email data uploaded to MinIO with key:", key)
	return nil
}

func (s *Session) Reset() {}

func (s *Session) Logout() error {
	duration := time.Since(s.startTime)
	log.Println("Session duration:", duration)
	return nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// Create a new MinIO client
	minioClient, err := minio.New(os.Getenv("MINIO_ENDPOINT"), os.Getenv("MINIO_ACCESS_KEY"), os.Getenv("MINIO_SECRET_KEY"), false)
	if err != nil {
		log.Fatal(err)
	}

	be := &Backend{
		minioClient: minioClient, // Pass the minioClient to the backend
	}

	s := smtp.NewServer(be)

	s.Addr = "0.0.0.0:1025"
	s.Domain = "localhost"
	s.WriteTimeout = 10 * time.Second
	s.ReadTimeout = 10 * time.Second
	s.MaxMessageBytes = 1024 * 1024
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
