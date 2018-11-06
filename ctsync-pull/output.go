package main

import (
	"bufio"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"sync"
)

func pushToFile(incoming <-chan string, wg *sync.WaitGroup, outputDirectory string) {
	defer wg.Done()

	if _, err := ioutil.ReadDir(outputDirectory); err != nil {
		log.Fatal(err)
	}

	counter := 0
	var currentFile *os.File
	var w *bufio.Writer
	var err error
	MaxEntriesPerFile := 1000
	for message := range incoming {
		if counter%MaxEntriesPerFile == 0 {
			if currentFile != nil {
				w.Flush()
				currentFile.Close()
			}
			filename := "log_entries_from_" + strconv.Itoa(counter+1) + ".csv"
			currentFile, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Fatal(err)
			}
		}
		counter += 1

		w = bufio.NewWriter(currentFile)
		w.WriteString(message)
		w.WriteString("\n")
	}

	w.Flush()
	currentFile.Close()
}
