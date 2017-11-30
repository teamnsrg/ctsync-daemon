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
	"flag"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"strings"
	"sync"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/op/go-logging"
	log "github.com/sirupsen/logrus"
)

var logger = logging.MustGetLogger("")

func updateCTLogInfoInDB(db *gorm.DB, config CTLogInfo) {
	var logConfig CTLogInfo
	db.Where("name = ?", config.Name).First(&logConfig)
	if db.Error != nil {
		log.Fatalf("error in querying database: %v", db.Error)
	}
	logConfig.Name = config.Name
	logConfig.BaseURL = config.BaseURL
	logConfig.BatchSize = config.BatchSize
	logConfig.LastIndex = config.LastIndex
	db.Save(&logConfig)
	if db.Error != nil {
		log.Fatalf("error in updating database: %v", db.Error)
	}
}

func updateDBWithCTLogInfo(db *gorm.DB, in <-chan CTLogInfo, wg *sync.WaitGroup) {
	defer wg.Done()
	for ctLogInfo := range in {
		updateCTLogInfoInDB(db, ctLogInfo)
	}
}

func updateLogInfoFromUpdater(updater chan int64, l CTLogInfo, logInfoOut chan CTLogInfo) {
	for {
		update := <-updater
		l.LastIndex = update
		logInfoOut <- l
	}
}

type runState struct {
	sync.RWMutex
	running bool
}

func (r *runState) stopRunning() {
	r.Lock()
	defer r.Unlock()
	r.running = false
}

func (r *runState) checkRunning() bool {
	r.RLock()
	defer r.RUnlock()
	return r.running
}

func main() {
	configFile := flag.String("config", "config.json", "The configuration file for log servers")
	brokerString := flag.String("brokers", "localhost:9092", "A comma separated list of the kafka broker locations")
	outTopic := flag.String("out-topic", "ct_to_zdb", "Kafka topic to place certificates in")
	dbPath := flag.String("db", "ctsync-pull.db", "Path to the SQLite file that stores log sync progress")
	numProcs := flag.Int("gomaxprocs", 0, "Number of processes to use")
	numFetch := flag.Int("fetchers", 1, "Number of workers assigned to fetch certificates from each server")
	numMatch := flag.Int("matchers", 1, "Number of workers assigned to parse certs from each server")
	flag.Parse()

	log.SetLevel(log.InfoLevel)
	runtime.GOMAXPROCS(*numProcs)
	brokers := strings.Split(*brokerString, ",")

	// Initialize Database
	db, err := gorm.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("could not open sqlite3 db: %s", err)
	}
	defer db.Close()
	db.AutoMigrate(&CTLogInfo{})

	// Read configuration file
	configuration, err := readAndLoadConfiguration(*configFile, db)
	if err != nil {
		log.Fatalf("could not load configuration file: %s", err)
	}

	// Connect to Kafka
	producer, err := createKafkaProducer(brokers)
	if err != nil {
		log.Fatalf("could not create kafka producer: %s", err)
	}

	// Clean up correctly
	running := runState{}
	running.running = true
	signalChannel := make(chan os.Signal, 3)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)
	var signalWg sync.WaitGroup
	signalWg.Add(1)
	go func() {
		for _ = range signalChannel {
			log.Info("received signal, halting")
			running.stopRunning()
		}
		signalWg.Done()
	}()

	// Start goroutine that produces certificates to Kafka.
	certificatesToKafka := make(chan []byte, 1000)
	var pushWg sync.WaitGroup
	pushWg.Add(1)
	go pushToKafka(certificatesToKafka, producer, *outTopic, &pushWg)

	// Start goroutine that writes indicies to SQLite
	logInfoUpdate := make(chan CTLogInfo)
	var dbWg sync.WaitGroup
	dbWg.Add(1)
	go updateDBWithCTLogInfo(db, logInfoUpdate, &dbWg)

	// Start goroutines that monitor a CTLog
	var pullWg sync.WaitGroup
	for i := 0; i < len(configuration); i++ {
		pullWg.Add(1)
		updater := make(chan int64)
		go pullFromCT(configuration[i], certificatesToKafka, updater, logInfoUpdate, *numMatch, *numFetch, &pullWg, &running)
		go updateLogInfoFromUpdater(updater, configuration[i], logInfoUpdate)
	}

	// Run until done pulling.
	pullWg.Wait()
	close(logInfoUpdate)
	dbWg.Wait()
	close(certificatesToKafka)
	pushWg.Wait()
	close(signalChannel)
	signalWg.Wait()
}
