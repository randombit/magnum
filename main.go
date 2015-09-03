package main

import (
	//"errors"
	"flag"
	"fmt"
	//"database/sql"
	//"io"
	//"io/ioutil"
	//"log"
	//"os"
	//"strings"

)

func main() {

	/*
Generate a certificate and stash it somewhere
Run the server
Have some way for a user to connect and submit a job
Spawn the EC2 instance, connect to it, bootstrap
start magnum fuzzball
which connects back to server
downloads the job the user provided
and runs afl, monitors output, reports crashes and stats back to mothership



*/

	// TODO default from env variables?
	serverFlag := flag.String("server", "", "name or IP of server")
	serverPortFlag := flag.Int("port", 8209, "server port")

	caCrtFlag := flag.String("ca", "ca.crt", "certificate file")
	caKeyFlag := flag.String("ca-key", "ca.key", "private key file")

	certFlag := flag.String("cert", "srv.crt", "certificate file")
	clientKeyFlag := flag.String("key", "srv.key", "private key file")

	dbFlag := flag.String("db", "magnum.db", "server database file")

	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Printf("Usage: magnum [server|job|fuzzball] [--server=] [--port=] [--cert] [--key] [--ca]\n")
		return
	}

	procType := flag.Arg(0)

	if (serverFlag == nil || *serverFlag == "") && procType != "genkeys" {
		fmt.Printf("Option --server required")
		return
	}

	srv := fmt.Sprintf("%s:%s", *serverFlag, *serverPortFlag)

	if procType == "fuzzball" {
		statusInterval := 3*60
		baseDir := "/dev/shm/magnum/"
		userInfo := ""
		Fuzzball(srv, baseDir, userInfo, statusInterval)

	} else if procType == "server" {
		MagnumServer(srv, *caCrtFlag, *caKeyFlag, *certFlag, *clientKeyFlag, *serverFlag,
			"", "", "us-east-1", *dbFlag)
	} else if procType == "job" {
		if dbFlag == nil {
			fmt.Printf("Database required for job manipulation")
		}

		subCmd := flag.Arg(1)

		if subCmd == "add" {
			//func CreateJob(db *sql.DB, binaryName, corpusDir, memo string, maxCph int) (error) {
		} else if subCmd == "list" {
			//func ListJobs(db* sql.DB) ([]string, error) {
		} else if subCmd == "stop" {
			//func StopJob(db* sql.DB, jobId string) (error) {
		}

	} else if procType == "genkeys" {


	} else {
		fmt.Printf("Unknown command type '%s'", procType)
		return
	}
}
