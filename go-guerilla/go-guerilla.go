package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/joho/godotenv"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/phires/go-guerrilla"
	"github.com/phires/go-guerrilla/backends"
	"github.com/phires/go-guerrilla/log"
	"github.com/phires/go-guerrilla/mail"
)

type StoreConfig struct {
	AccessKey   string `json:"access_key"`
	SecretKey   string `json:"secret_key"`
	EndpointURL string `json:"endpoint_url"`
	EsURL       string `json:"es_url"`
	EsApiKey    string `json:"es_api_key"`
}

var StoreProcessor = func() backends.Decorator {
	var storeConfig *StoreConfig
	var minioClient *minio.Client
	var esClient *elasticsearch.Client

	backends.Svc.AddInitializer(backends.InitializeWith(func(backendConfig backends.BackendConfig) error {
		configType := backends.BaseConfig(&StoreConfig{})
		bcfg, err := backends.Svc.ExtractConfig(backendConfig, configType)
		if err != nil {
			return err
		}
		storeConfig = bcfg.(*StoreConfig)

		esCfg := elasticsearch.Config{
			Addresses: []string{storeConfig.EsURL},
			APIKey:    storeConfig.EsApiKey,
		}

		esClient, err = elasticsearch.NewClient(esCfg)
		if err != nil {
			backends.Log().WithError(err).Error(err, " Unable to connect to Elasticsearch: ", esClient)
		} else {
			es, err := esClient.Info()
			if err != nil {
				backends.Log().WithError(err).Error(err, " Unable to get Elasticsearch info: ", es)
			} else {
				backends.Log().Info("Elasticsearch: ", es)
			}
		}

		minioClient, err = minio.New(storeConfig.EndpointURL, &minio.Options{
			Creds:  credentials.NewStaticV4(storeConfig.AccessKey, storeConfig.SecretKey, ""),
			Secure: false,
		})
		if err != nil {
			return err
		}
		res, err := minioClient.PutObject(context.Background(), "messages", "TESTPUT", strings.NewReader("TESTPUT"), -1, minio.PutObjectOptions{ContentType: "text/plain"})
		if err != nil {
			backends.Log().WithError(err).Error(err, " Unable to PUT TESTPUT object; minio: ", res)
		}
		backends.Log().Info("Test Object PUT ", res)

		return nil
	}))

	return func(p backends.Processor) backends.Processor {
		return backends.ProcessWith(
			func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
				if task == backends.TaskValidateRcpt {

					// if you want your processor to validate recipents,
					// validate recipient by checking
					// the last item added to `e.RcptTo` slice
					// if error, then return something like this:
					/* return backends.NewResult(
					   response.Canned.FailNoSenderDataCmd),
					   backends.NoSuchUser
					*/
					// if no error:
					return p.Process(e, task)
				} else if task == backends.TaskSaveMail {

					type Envelope struct {
						MailFrom string   `json:"mail_from"`
						RcptTo   []string `json:"rcpt_to"`
						Ehlo     string   `json:"ehlo"`
						RemoteIp string   `json:"remote_ip"`
						TLS      bool     `json:"tls"`
						QueuedId string   `json:"queued_id"`
					}
					type Document struct {
						Envelope Envelope            `json:"envelope"`
						Headers  map[string][]string `json:"headers"`
						StoreUrl string              `json:"store_url"`
						StoredIn time.Duration       `json:"stored_in"`
						Date     time.Time           `json:"date"`
					}

					document := Document{}
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
						if e.Header[header] != nil {
							document.Headers[header] = e.Header.Values(header)
						}
					}

					start := time.Now()

					// PUT full message contents to minio
					// TODO check for connection reuse (res.Close())
					res, err := minioClient.PutObject(context.Background(), "messages", e.QueuedId, e.NewReader(), -1, minio.PutObjectOptions{ContentType: "message/rfc822"})
					if err != nil {
						backends.Log().WithError(err).Error(err, " minio: ", res)
						return backends.NewResult(fmt.Sprintf("451 Error: %s", err)), err
					} else {
						backends.Log().Debug("id: ", e.QueuedId, " minio: ", res)

					}
					// if want to stop processing, return
					// errors.New("Something went wrong")
					// return backends.NewBackendResult(fmt.Sprintf("554 Error: %s", err)), err
					// call the next processor in the chain
					elapsed := time.Since(start)
					backends.Log().Debug("stored in: ", elapsed)

					document.Envelope.MailFrom = e.MailFrom.String()
					for _, rcpt := range e.RcptTo {
						document.Envelope.RcptTo = append(document.Envelope.RcptTo, rcpt.String())
					}
					document.Envelope.Ehlo = e.Helo
					document.Envelope.RemoteIp = e.RemoteIP
					document.Envelope.TLS = e.TLS
					document.Envelope.QueuedId = e.QueuedId
					document.StoreUrl = res.Location
					document.StoredIn = elapsed
					document.Date = time.Now()

					esdata, _ := json.Marshal(document)
					esClient.Index("messages", bytes.NewReader(esdata))

					return p.Process(e, task)
				} else {
					return p.Process(e, task)
				}
			},
		)
	}
}

var DkimProcessor = func() backends.Decorator {
	return func(p backends.Processor) backends.Processor {
		return backends.ProcessWith(
			func(e *mail.Envelope, task backends.SelectTask) (backends.Result, error) {
				if task == backends.TaskValidateRcpt {

					// if you want your processor to validate recipents,
					// validate recipient by checking
					// the last item added to `e.RcptTo` slice
					// if error, then return something like this:
					/* return backends.NewResult(
					   response.Canned.FailNoSenderDataCmd),
					   backends.NoSuchUser
					*/
					// if no error:
					return p.Process(e, task)
				} else if task == backends.TaskSaveMail {
					start := time.Now()

					dkimSignature := e.Header.Get("DKIM-Signature")
					if dkimSignature != "" {
						// verify DKIM signature
						backends.Log().Debug("DKIM-Signature: ", dkimSignature)
						// perform operations with dkimSignature
					}

					elapsed := time.Since(start)
					backends.Log().Debug("dkim in: ", elapsed)
					return p.Process(e, task)
				}
				return p.Process(e, task)
			},
		)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file [%s]", err)
	}

	cfg := &guerrilla.AppConfig{LogFile: log.OutputStdout.String(), AllowedHosts: []string{"."}}
	sc := guerrilla.ServerConfig{
		ListenInterface: ":2526",
		IsEnabled:       true,
	}
	cfg.Servers = append(cfg.Servers, sc)
	bcfg := backends.BackendConfig{
		"save_workers_size":  1,
		"save_process":       "HeadersParser|Header|Hasher|Store",
		"log_received_mails": true,
		"primary_mail_host":  "example.com",
		"access_key":         os.Getenv("MINIO_ACCESS_KEY"),
		"secret_key":         os.Getenv("MINIO_SECRET_KEY"),
		"endpoint_url":       os.Getenv("MINIO_ENDPOINT"),
		"es_url":             os.Getenv("ES_URL"),
		"es_api_key":         os.Getenv("ES_API_KEY"),
	}
	cfg.BackendConfig = bcfg

	d := guerrilla.Daemon{Config: cfg}
	d.AddProcessor("Store", StoreProcessor)
	d.AddProcessor("Dkim", DkimProcessor)

	err = d.Start()
	if err == nil {
		fmt.Println("Server Started!")
	}

	select {}
}
