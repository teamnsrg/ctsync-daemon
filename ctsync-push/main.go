/*
 *  CTSync Daemon Copyright 2017 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	oldLog "log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Shopify/sarama"
	"github.com/bsm/sarama-cluster"
	zsearch "github.com/censys/censys-definitions/go/censys-definitions"
	"github.com/golang/protobuf/proto"
	"github.com/op/go-logging"
	"github.com/teamnsrg/zcrypto/ct"
	"github.com/teamnsrg/zcrypto/ct/client"
	"github.com/teamnsrg/zcrypto/ct/x509"
	zx509 "github.com/teamnsrg/zcrypto/x509"
)

type Stats struct {
	Successes       int64
	Failures        int64
	ForbiddenErrors int64
}

const ForbiddenErrorsToFail = 4

var roots *x509.CertPool
var intermediates *x509.CertPool
var storeLock sync.RWMutex
var stats Stats

type Logger struct {
	Log *logging.Logger
}

func (l Logger) Print(x ...interface{}) {
	l.Log.Debug(x)
}

func (l Logger) Println(x ...interface{}) {
	l.Log.Debug(x, "\n")
}

func (l Logger) Printf(format string, x ...interface{}) {
	l.Log.Debugf(format, x)
}

var log = logging.MustGetLogger("")
var logInterface = Logger{log}

type Server struct {
	Url         string
	Name        string
	TokenBucket uint64
}

type Configuration struct {
	Expired   []Server
	Unexpired []Server
}

var configuration Configuration

// Example format string. Everything except the message has a custom color
// which is dependent on the log level. Many fields have a custom output
// formatting too, eg. the time returns the hour down to the milli second.
var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

func statOutputter(duration time.Duration) {
	var last time.Time
	lastStats := stats
	first := true
	ticker := time.NewTicker(duration)
	for current := range ticker.C {
		if first {
			first = false
		} else {
			since := time.Since(last)
			log.Noticef("Successful submissions to logs: %d (%f per second)\n", stats.Successes, float64(stats.Successes-lastStats.Successes)/since.Seconds())
			log.Noticef("Failed     submissions to logs: %d (%f per second)\n", stats.Failures, float64(stats.Failures-lastStats.Failures)/since.Seconds())
			log.Noticef("Forbidden  submissions to logs: %d (%f per second)\n", stats.ForbiddenErrors, float64(stats.ForbiddenErrors-lastStats.ForbiddenErrors)/since.Seconds())
		}
		lastStats = stats
		last = current
	}
}

func channelRefiller(workRate uint64) {
	ticker := time.NewTicker(time.Second)
	for _ = range ticker.C {
		log.Debugf("Putting %d tokens in the buckets\n", workRate)
		for i, _ := range configuration.Expired {
			configuration.Expired[i].TokenBucket = workRate
		}
		for i, _ := range configuration.Unexpired {
			configuration.Unexpired[i].TokenBucket = workRate
		}
	}
}

func initialize(rootFile, intermediateFile, configFile, output string, logLevel int, workRate uint64) {
	oldLog.SetOutput(ioutil.Discard)
	var f *os.File
	if output == "-" {
		f = os.Stderr
	} else {
		var err error
		f, err = os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
	}
	backend := logging.NewLogBackend(f, "", 0)
	backendFormat := logging.NewBackendFormatter(backend, format)
	backendLeveled := logging.AddModuleLevel(backendFormat)
	backendLeveled.SetLevel(logging.Level(logLevel), "")
	logging.SetBackend(backendLeveled)
	sarama.Logger = logInterface
	log.Debugf("Input Log level: %d %s", logging.Level(logLevel), logging.Level(logLevel).String())
	log.Debugf("Log level: %d %s", backendLeveled.GetLevel(""), backendLeveled.GetLevel("").String())
	loadServers(configFile)
	loadCertificates(rootFile, intermediateFile)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGUSR1)
		for sig := range c {
			log.Info("Signal!")
			if sig == syscall.SIGTERM || sig == syscall.SIGINT || sig == syscall.SIGKILL {
				log.Info("Received a signal:", sig, ". Shutting down.")
				os.Exit(1)
				break
			} else if sig == syscall.SIGUSR1 {
				log.Info("Received a signal:", sig, ". Reloading Stores.")
				loadCertificates(rootFile, intermediateFile)
			} else {
				log.Info("Received a signal:", sig, ". Ignoring.")
			}
		}
	}()
	go statOutputter(time.Second * 5)
	go channelRefiller(workRate)
}

func loadCertificates(rootFile, intermediateFile string) {
	storeLock.Lock()
	infile, err := os.Open(rootFile)
	if err != nil {
		log.Fatal(err)
	}
	bytes, err := ioutil.ReadAll(infile)
	if err != nil {
		log.Fatal(err)
	}
	roots = x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(bytes)
	if !ok {
		log.Fatal("Could not load root PEM")
	}
	infile.Close()
	infile, err = os.Open(intermediateFile)
	if err != nil {
		log.Fatal(err)
	}
	bytes, err = ioutil.ReadAll(infile)
	if err != nil {
		log.Fatal(err)
	}
	intermediates = x509.NewCertPool()
	ok = intermediates.AppendCertsFromPEM(bytes)
	if !ok {
		log.Fatal("Could not load intermediate PEM")
	}
	infile.Close()
	storeLock.Unlock()
}

func loadServers(configFile string) {
	config, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(config, &configuration)
	if err != nil {
		log.Fatal(err)
	}
}

func fetcher(forward chan<- *zsearch.Certificate, consumer *cluster.Consumer) {
	log.Debug("Listening to Kafka")
	for {
		select {
		case msg := <-consumer.Messages():
			log.Debug("Got certificate from Kafka")
			var recvd zsearch.AnonymousDelta
			err := proto.Unmarshal(msg.Value, &recvd)
			if err != nil {
				log.Warning(err)
				continue
			}
			forward <- recvd.Record.OneofData.(*zsearch.AnonymousRecord_Certificate).Certificate
			consumer.MarkOffset(msg, "")
		case err := <-consumer.Errors():
			log.Info(err)
		}
	}
	_ = consumer.Close()
}

func packSCT(sct *ct.SignedCertificateTimestamp) ([]byte, error) {
	if sct == nil {
		return nil, errors.New("Nil SCT provided")
	}
	packed := new(bytes.Buffer)
	err := binary.Write(packed, binary.BigEndian, sct.SCTVersion)
	if err != nil {
		return nil, err
	}
	packed.Write(sct.LogID[:])
	err = binary.Write(packed, binary.BigEndian, sct.Timestamp)
	if err != nil {
		return nil, err
	}
	err = binary.Write(packed, binary.BigEndian, uint16(len(sct.Extensions)))
	if err != nil {
		return nil, err
	}
	packed.Write(sct.Extensions)
	packed.Write([]byte{byte(sct.Signature.HashAlgorithm), byte(sct.Signature.SignatureAlgorithm)})
	err = binary.Write(packed, binary.BigEndian, uint16(len(sct.Signature.Signature)))
	if err != nil {
		return nil, err
	}
	packed.Write(sct.Signature.Signature)
	return packed.Bytes(), nil
}

func inLog(log *zsearch.CTServerStatus) bool {
	if log == nil {
		return false
	}
	return log.Index != 0 && log.PushStatus != zsearch.CTPushStatus_CT_PUSH_STATUS_RESERVED
}

func grabToken(bucket *uint64) {
	log.Debug("Grabbing token")
	grabbed := false
	for !grabbed {
		old := *bucket
		if old == 0 {
			time.Sleep(time.Millisecond * 10)
			continue
		}
		next := old - 1
		grabbed = atomic.CompareAndSwapUint64(bucket, old, next)
	}
	log.Debug("Grabbed token")
}

func submitCertificate(client *client.LogClient, logName string, cert *zsearch.Certificate, submission []ct.ASN1Cert, topic string, producer sarama.SyncProducer) {
	sending := &zsearch.SCT{
		Sha256Fp: cert.Sha256Fp,
		Server:   zsearch.CTServer(zsearch.CTServer_value[logName]),
	}
	log.Debugf("Sending chain for %s to server %s\n", hex.EncodeToString(cert.Sha256Fp), logName)
	sct, err, errorCode := client.AddChain(submission)
	if err != nil || sct == nil {
		if errorCode == 403 {
			errorCount := atomic.AddInt64(&stats.ForbiddenErrors, 1)
			if errorCount > ForbiddenErrorsToFail {
				log.Fatalf("Received %d 403 Forbidden Errors\n", errorCount)
			}
		} else {
			stats.ForbiddenErrors = 0
		}
		status := zsearch.CTServerStatus{
			PushStatus:    zsearch.CTPushStatus_CT_PUSH_STATUS_UNKNOWN_ERROR,
			PushTimestamp: time.Now().Unix(),
			PushError:     err.Error(),
		}
		sending.Status = &status
		log.Infof("No SCT: %s: %s\n", hex.EncodeToString(cert.Sha256Fp), err)
		atomic.AddInt64(&stats.Failures, 1)
	} else {
		log.Debugf("Got SCT that is %f seconds old.", time.Now().Sub(time.Unix(int64(sct.Timestamp/1000), 0)).Seconds())
		if time.Now().Sub(time.Unix(int64(sct.Timestamp/1000), 0)).Seconds() < 30 {
			packed, err := packSCT(sct)
			if err != nil {
				log.Fatal("Failed packing SCT: ", err)
			}
			status := zsearch.CTServerStatus{
				PushStatus:    zsearch.CTPushStatus_CT_PUSH_STATUS_SUCCESS,
				PushTimestamp: int64(sct.Timestamp),
				Sct:           packed,
			}
			sending.Status = &status
		} else {
			log.Debugf("Old SCT: %s\n", hex.EncodeToString(cert.Sha256Fp))
			status := zsearch.CTServerStatus{
				PushStatus:    zsearch.CTPushStatus_CT_PUSH_STATUS_ALREADY_EXISTS,
				PushTimestamp: int64(sct.Timestamp),
			}
			sending.Status = &status
		}
		data, err := proto.Marshal(sending)
		if err != nil {
			log.Warningf("marshaling error: %s\n", err)
			return
		}
		msg := &sarama.ProducerMessage{Topic: topic, Value: sarama.StringEncoder(data)}
		log.Debugf("Sending SCT to Kafka topic %s\n", topic)
		_, _, err = producer.SendMessage(msg)
		if err != nil {
			log.Fatal("Failed to send message: %s: %s\n", hex.EncodeToString(cert.Sha256Fp), err)
			atomic.AddInt64(&stats.Failures, 1)
		} else {
			atomic.AddInt64(&stats.Successes, 1)
			log.Debug("Success sending")
			log.Debug(hex.EncodeToString(cert.Sha256Fp))
		}
	}
}

func worker(wg *sync.WaitGroup, recvd <-chan *zsearch.Certificate, producer sarama.SyncProducer, unexpired []*client.LogClient, expired []*client.LogClient, topic string) {
	currentUnexpiredIndex := 0
	currentExpiredIndex := 0
	for cert := range recvd {
		if cert.Ct != nil && (inLog(cert.Ct.GoogleAviator) || inLog(cert.Ct.GooglePilot) || inLog(cert.Ct.GoogleRocketeer) || inLog(cert.Ct.GoogleSubmariner) || inLog(cert.Ct.GoogleIcarus) || inLog(cert.Ct.GoogleSkydiver) || inLog(cert.Ct.GoogleDaedalus)) {
			log.Debugf("Already in CT: %s\n", hex.EncodeToString(cert.Sha256Fp))
			atomic.AddInt64(&stats.Successes, 1)
			continue
		}
		parsed, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			log.Infof("x509 Error: %s: %s\n", hex.EncodeToString(cert.Sha256Fp), err)
			atomic.AddInt64(&stats.Failures, 1)
			continue
		}
		if parsed.IsPrecert {
			log.Debugf("Precert: %s\n", hex.EncodeToString(cert.Sha256Fp))
			atomic.AddInt64(&stats.Successes, 1)
			continue
		}
		storeLock.RLock()
		opts := x509.VerifyOptions{
			DNSName:       "",
			Intermediates: intermediates,
			Roots:         roots,
			CurrentTime:   parsed.NotBefore,
			KeyUsages:     []x509.ExtKeyUsage{},
		}
		chains, err := parsed.Verify(opts)
		storeLock.RUnlock()
		//If the certificate was ever valid
		if err == nil && len(chains) > 0 {
			var submission []ct.ASN1Cert
			chainString := ""
			for _, cert := range chains[0] {
				if logging.GetLevel("") > 4 {
					parsed, err := zx509.ParseCertificate(cert.Raw)
					if err == nil {
						chainString = chainString + hex.EncodeToString(parsed.FingerprintSHA256) + ","
					}
				}
				submission = append(submission, cert.Raw)
			}
			log.Debugf("Found chain to: %s: %s\n", hex.EncodeToString(cert.Sha256Fp), chainString)
			var client *client.LogClient
			var logName string
			//Choose which log to send it to depending on the NotBefore and NotAfter
			if !time.Now().After(parsed.NotAfter) && !time.Now().Before(parsed.NotBefore) {
				grabToken(&(configuration.Unexpired[currentUnexpiredIndex].TokenBucket))
				client = unexpired[currentUnexpiredIndex]
				logName = configuration.Unexpired[currentUnexpiredIndex].Name
				currentUnexpiredIndex = (currentUnexpiredIndex + 1) % len(unexpired)
			} else {
				grabToken(&(configuration.Expired[currentExpiredIndex].TokenBucket))
				client = expired[currentExpiredIndex]
				logName = configuration.Expired[currentExpiredIndex].Name
				currentExpiredIndex = (currentExpiredIndex + 1) % len(expired)
			}
			submitCertificate(client, logName, cert, submission, topic, producer)
		} else {
			// This is the case for self-signed, untrusted root, etc.
			log.Debugf("Invalid Certificate: %s: Error: %s\n", hex.EncodeToString(cert.Sha256Fp), err)
		}
	}
	wg.Done()
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func kafkaConsumer(recvTopic string, brokers []string) (*cluster.Consumer, error) {
	config := cluster.NewConfig()
	config.ClientID = "ct-push-daemon"
	config.Consumer.MaxProcessingTime = time.Minute
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	return cluster.NewConsumer(brokers, "ct-push-daemon", []string{recvTopic}, config)
}

func makeClients(servers []Server) []*client.LogClient {
	var ret []*client.LogClient
	for _, server := range servers {
		c := client.New(server.Url)
		ret = append(ret, c)
	}
	return ret
}

func main() {
	brokerString := flag.String("brokers", "127.0.0.1:9092", "a comma separated list of the brokers")
	recvTopic := flag.String("receive-topic", "certificate_deltas", "the kafka topic to get certificates from")
	sendTopic := flag.String("send-topic", "scts", "the kafka topic to put SCTs on")
	output := flag.String("log", "-", "log file")
	configFile := flag.String("config", "config.json", "a configuration, specifying what logs to send certificates to")
	rootFile := flag.String("root", "/etc/nss-root-store.pem", "an nss root store, defaults to etc/nss-root-store.pem")
	intermediateFile := flag.String("intermediate", "/etc/nss-intermediate-store.pem", "an nss intermediate store, defaults to etc/nss-intermediate-store.pem")
	numProcs := flag.Int("proc", 1, "Number of processes to run on")
	numWork := flag.Int("senders", 1, "Number of workers assigned to send certs to ct")
	workRate := flag.Uint64("rate", 10, "Number of requests per second, per server")
	logLevel := flag.Int("log-level", 0, "log level")
	flag.Parse()

	runtime.GOMAXPROCS(*numProcs)
	initialize(*rootFile, *intermediateFile, *configFile, *output, *logLevel, *workRate)
	brokers := strings.Split(*brokerString, ",")
	consumer, err := kafkaConsumer(*recvTopic, brokers)
	if err != nil {
		log.Fatal(err)
	}
	certs := make(chan *zsearch.Certificate)
	go fetcher(certs, consumer)
	log.Info("Launched consumers")
	wg := &sync.WaitGroup{}
	for i := 0; i < *numWork; i++ {
		conf := sarama.NewConfig()
		conf.ClientID = "sct_producer"
		conf.Producer.Return.Successes = true
		producer, err := sarama.NewSyncProducer(brokers, conf)
		if err != nil {
			log.Fatal(err)
		}
		wg.Add(1)
		go worker(wg, certs, producer, makeClients(configuration.Unexpired), makeClients(configuration.Expired), *sendTopic)
	}
	log.Info("Launched workers")
	wg.Wait()
	_ = consumer.Close()
}
