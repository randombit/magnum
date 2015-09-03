package main

import (
	"bytes"
	"crypto/tls"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"path"
	"database/sql"
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	//"os"
	"strings"
	"time"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/ec2"
	_ "github.com/mattn/go-sqlite3"
)

type ServerState struct {
	PublicIP string
	Db *sql.DB
	Ec2 *ec2.EC2

	CaCert *x509.Certificate
	CaCertPem string
	CaSigner crypto.PrivateKey
}

func LogRequest(req *http.Request) {
	reqBytes, err := httputil.DumpRequest(req, true)
	if err != nil {
		log.Fatal(err) // ??
	}
	fmt.Printf("%s", reqBytes)

	return
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Method = %s\n", req.Method))
	for k, v := range req.Header {
		buffer.WriteString(fmt.Sprintf("Header %s = %s\n", k, v));
	}

	for k, v := range req.Form {
		buffer.WriteString(fmt.Sprintf("Form %s = %s\n", k, v));
	}

	for k, v := range req.PostForm {
		buffer.WriteString(fmt.Sprintf("PostForm %s = %s\n", k, v));
	}

	fmt.Println(buffer.String())
}

func getParam(req *http.Request, key string) (string, error) {

	val, ok := req.Form[key]

	if ok {
		if len(val) > 0 {
			return val[0], nil
		}
	}
	return "", errors.New(fmt.Sprintf("Param '%s' not found in form", key))
}

func httpErrorStr(w http.ResponseWriter, errcode int, errstr string) int {
	if errcode != http.StatusOK {
		log.Print("Request failed %s", errstr);
	}

	http.Error(w, errstr, errcode)
	return errcode
}

func httpError(w http.ResponseWriter, errcode int, err error) int {
	return httpErrorStr(w, errcode, err.Error())
}

func httpStandardError(w http.ResponseWriter, errcode int) int {
	return httpErrorStr(w, errcode, http.StatusText(errcode))
}

func getPeerName(tls *tls.ConnectionState) (string, error) {
	if tls == nil {
		return "", errors.New("TLS required")
	}

	if len(tls.VerifiedChains) == 0 {
		return "", errors.New("No verified chains")
	}

	if len(tls.VerifiedChains[0]) == 0 {
		return "", errors.New("Chain is empty")
	}

	return tls.VerifiedChains[0][0].Subject.CommonName, nil
}

func HandleNodeStartup(w http.ResponseWriter, req *http.Request, db *sql.DB) int {

	nodeId, err := getPeerName(req.TLS)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	fmt.Printf("startup from %s at address '%s'", nodeId, req.RemoteAddr)

	if req.Method != "POST" {
		log.Print("Bad login method '%s'", req.Method)
		return httpStandardError(w, http.StatusMethodNotAllowed)
	}
	req.ParseForm()

	LogRequest(req)

	/*
	id, err := getParam(req, "NodePublicIP")
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}
*/

	tx, err := db.Begin()
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	stmt, err := tx.Prepare("update magnum_node set address=?, started=datetime('now') where instanceId=?")
	if err != nil {
		return httpError(w, http.StatusInternalServerError, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(req.RemoteAddr, nodeId)

	if err != nil {
		return httpError(w, http.StatusInternalServerError, err)
	}
	tx.Commit()

	workRow, err := db.Query("select j.blob from magnum_job j, magnum_node n where n.nodeId = ? and j.jobId = n.jobId", nodeId)
	defer workRow.Close()
	var work string
	for workRow.Next() {
		workRow.Scan(&work)
	}

	if work == "" {
		return httpErrorStr(w, http.StatusInternalServerError, "No job found for this node")
	}

	io.WriteString(w, work)
	return http.StatusOK
}

func addToTar(tw *tar.Writer, readFileName, writeFileName string) (error) {
	contents, err := ioutil.ReadFile(readFileName)
	if err != nil {
		log.Printf("Error reading file", readFileName, err)
		return err
	}

	hdr := &tar.Header{Name:writeFileName, Mode: 0600, Size: int64(len(contents))}
	err = tw.WriteHeader(hdr)
	if err != nil {
		log.Printf("Error writing tar header for file", readFileName, err)
		return err
	}

	_, err = tw.Write(contents)
	if err != nil {
		log.Printf("Error writing tar contents for file", readFileName, err)
		return err
	}

	return nil
}


func CreateJob(db *sql.DB, binaryName, corpusDir, memo string, maxCph int) (error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	dir, err := ioutil.ReadDir(corpusDir)
	if err != nil {
		return err
	}

	for _, fi := range dir {
		fileName := fi.Name()
		err = addToTar(tw, path.Join(corpusDir, fileName), path.Join("corpus", fileName))
		if err != nil {
			return err
		}
	}

	err = addToTar(tw, binaryName, "target")
	if err != nil {
		return err
	}

	work := base64.StdEncoding.EncodeToString(buf.Bytes())

	jobId := createId("job")
	db.Exec("insert into magnum_job values(?, ?, ?, ?, datetime('now'), '')", jobId, memo, work, maxCph)
	return nil
}

func ListJobs(db* sql.DB) ([]string, error) {
	rows, err := db.Query("select jobId, memo, started, ended from magnum_job")
	if err != nil {
		fmt.Printf("Scan filed %s", err)
		return nil, err
	}

	jobs := []string{}
	for rows.Next() {
		var jobId, memo string
		var started, ended time.Time
		err = rows.Scan(&jobId, &memo, &started, &ended)
		if err != nil {
			fmt.Printf("Scan failed %s", err)
			return nil, err
		}

		fmt.Printf("Job %s (%s) started %s stopped %s\n", jobId, memo, started, ended)
		jobs = append(jobs, fmt.Sprintf("%s,%s,%s,%s",  jobId, memo, started, ended))
	}

	return jobs, nil
}

func StopJob(db* sql.DB, jobId string) (error) {
	// This just updates the db field; instances are terminated at next job evaluation
	_, err := db.Exec("update magnum_job set ended=datetime('now') where jobId=?", jobId)
	if err != nil {
		return err
	}
	return nil
}

func HandleStatus(w http.ResponseWriter, req *http.Request, db* sql.DB) int {
	nodeId, err := getPeerName(req.TLS)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	if req.Method != "POST" {
		return httpStandardError(w, http.StatusMethodNotAllowed)
	}
	req.ParseForm()
	LogRequest(req)

	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}
	// Check that nodeId is known to us

	executions, err := getParam(req, "TotalExecutions")
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	fuzzersRunning, err := getParam(req, "FuzzersRunning")
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	pathsFound, err := getParam(req, "PathsFound")
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	fmt.Printf("Status update from %s running %d fuzzers %d execs %d paths\n", nodeId, executions, fuzzersRunning, pathsFound)

	res, err := db.Exec("update magnum_node set executions=?, fuzzersRunning=?, lastUpdate=datetime('now') where instanceId=?",
		executions, fuzzersRunning, nodeId)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	affected, err := res.RowsAffected()
	if affected != 1 || err != nil{
		return httpErrorStr(w, http.StatusBadRequest, "No rows")
	}

	return http.StatusOK
}

func HandleGetBlob(w http.ResponseWriter, req *http.Request, db* sql.DB) int {
	/*
	nodeId, err := getPeerName(req.TLS)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}
*/

	if req.Method == "GET" {
		params := strings.Split(req.URL.Path, "/")

		if len(params) <= 1 {
			return httpErrorStr(w, http.StatusBadRequest, "Missing param")
		}
		blobId := params[len(params)-1]

		fmt.Printf("Client requested blob %s\n", blobId)
		if len(blobId) != 64 {
			return httpErrorStr(w, http.StatusBadRequest, "Invalid blob id")
		}
		// todo check that it is hex

		stmt, err := db.Prepare("select bin from magnum_blob where blobid=?")
		if err != nil {
			return httpErrorStr(w, http.StatusBadRequest, "Blob not found")
		}
		defer stmt.Close()

		var blob []byte
		//var blob bytes.Buffer
		err = stmt.QueryRow(blobId).Scan(&blob)
		if err != nil {
			//???
			return httpError(w, http.StatusInternalServerError, err)
		}

		w.Header().Set("Content-Type", "application/octet-string")
		w.Write(blob)
		return http.StatusOK
	} else {
		return httpStandardError(w, http.StatusMethodNotAllowed)
	}
}

func getJobOf(nodeId string, db* sql.DB) (string, error) {
	rows, err := db.Query("select jobId from magnum_node where nodeId=?")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var jobId string
	for rows.Next() {
		rows.Scan(&jobId)
	}
	return jobId, nil
}

func HandleResult(w http.ResponseWriter, req *http.Request, db* sql.DB) int {
	nodeId, err := getPeerName(req.TLS)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	if req.Method == "POST" {
		// Check MIME types?
		req.ParseForm()
		resultType, err := getParam(req, "Type")
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}
		resultValue, err := getParam(req, "Result")
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}

		jobId, err := getJobOf(nodeId, db)
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}

		db.Exec("insert into magnum_result values(?, ?, ?)", jobId, resultType, resultValue)
		return http.StatusOK
	} else {
		return httpStandardError(w, http.StatusMethodNotAllowed)
	}
}

func HandleWorkerSync(w http.ResponseWriter, req *http.Request, db* sql.DB) int {
	nodeId, err := getPeerName(req.TLS)
	if err != nil {
		return httpError(w, http.StatusBadRequest, err)
	}

	if req.Method == "POST" {
		req.ParseForm()

		mimeType, found := req.Header["Content-Type"]
		if ! found || len(mimeType) != 1 || mimeType[0] != "application/octet-string" {
			return httpErrorStr(w, http.StatusBadRequest, "Bad Content-Type")
		}

		contents, err := ioutil.ReadAll(req.Body)
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}

		// assumes line was already created
		stmt, err := tx.Prepare("update magnum_node set blob=?, last=datetime('now') where nodeId=?")

		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}
		defer stmt.Close()

		_, err = stmt.Exec(contents, nodeId)
		if err != nil {
			return httpError(w, http.StatusInternalServerError, err)
		}

		err = tx.Commit()
		if err != nil { return httpError(w, http.StatusInternalServerError, err) }
	} else if req.Method == "GET" {
		return httpErrorStr(w, http.StatusMethodNotAllowed, "not implemented")
		//
	} else {
		return httpStandardError(w, http.StatusMethodNotAllowed)
	}
	return http.StatusOK
}


func wrapHandler(db* sql.DB, fn func (http.ResponseWriter, *http.Request, *sql.DB) int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { fn(w, r, db) }
}

func addBinaryToDB(db *sql.DB, binary []byte) error {
	stmt, err := db.Prepare("insert into magnum_blob values(?, ?)")
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer stmt.Close()

	binId := hexSha256(binary)

	_, err = stmt.Exec(binId, binary)
	return nil
}

func addBinaryAtPathDB(db *sql.DB, path string) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return addBinaryToDB(db, contents)
}

func initDatabase(db *sql.DB) (error) {
	// SCHEMA
	magnumSchema := `create table if not exists magnum_blob(blobId string, bin blob);
	create table if not exists magnum_job (jobId string primary key, memo string, blob string, maxCph int, started datetime, ended datetime);
        create table if not exists magnum_node (nodeId string primary key, jobId string, instanceId string, spotReqId string, syncBlob string, syncTime datetime, address string, keyName string, maxCph int, execs int, started datetime, ended datetime);
        create table if not exists magnum_result (jobId string, type string, input blob);
        create table if not exists magnum_instance_keys (keyName string, secretKey string);
	`
	_, err := db.Exec(magnumSchema)
	return err
}


func CreateOrLoadKeyPair(db *sql.DB, svc* ec2.EC2) (string, string, error) {

	// TODO: store creation times and select most recent, to occasionally cycle?

	// TODO: scan all currently running instances and delete old keys which are not in use

	keyRow, err := db.Query("select top 1 from magnum_instance_keys")

	for keyRow.Next() {
		var keyName, keyString string
		err = keyRow.Scan(&keyName, &keyString)
		if err != nil {
			return "", "", err
		}

		// TODO: check that keyName exists in AWS
		// TODO: check that keyFingerprint in AWS matches our key
		return keyName, keyString, nil
	}

	keyName := createId("magnum_node_key")

	resp, err := svc.CreateKeyPair(&ec2.CreateKeyPairInput{KeyName: &keyName,})
	if err != nil {
		return "", "", err
	}
	keyString := *resp.KeyMaterial
	// TODO sanity check this value

	_, err = db.Exec("insert into magnum_instance_keys values(?,?)", keyName, keyString)
	if err != nil {
		fmt.Printf("Error saving key material to db", err)
		return "", "", nil
	}
	return keyName, keyString, nil
}

func generateUserDataFor(serverIP, nodeId string, caCert *x509.Certificate,
	caCertPem string, caKey crypto.PrivateKey) (string, error) {

	bootstrapBytes, err := ioutil.ReadFile("bootstrap.sh")
	if err != nil {
		return "", err
	}

	aflVersion := "1.94b"
	bootstrap := string(bootstrapBytes)

	nodeCert, nodeKey, err := generateNodeCert(nodeId, caCert, caKey)

	if err != nil {
		return "", err
	}

	bootstrap = strings.Replace(bootstrap, "%{magnum_server}", serverIP, -1)
	bootstrap = strings.Replace(bootstrap, "%{afl_version}", aflVersion, -1)
	bootstrap = strings.Replace(bootstrap, "%{ca_cert}", caCertPem, -1)
	bootstrap = strings.Replace(bootstrap, "%{client_cert}", nodeCert, -1)
	bootstrap = strings.Replace(bootstrap, "%{client_key}", nodeKey, -1)

	return bootstrap, nil
}


func MaybeRequestInstances(st* ServerState, jobId string, jobCph int, instances []*string, spotReqs []*string) error {

	if len(instances) == 0 && len(spotReqs) == 0 {
		nodeId := createId("magnum_node")
		amiId := "ami-e3106686" // FIXME
		instType := "m3.medium" // FIXME
		_, keyId, err := CreateOrLoadKeyPair(st.Db, st.Ec2)
		if err != nil {
			return err
		}
		maxCph := jobCph

		_, err = st.Db.Exec("insert into magnum_node values(?, ?, '', '', '', '', '', ?, ?, 0, datetime('now'), '')", nodeId, jobId, keyId, maxCph)

		if err != nil {
			fmt.Printf("Error creating new node entry", err)
			return err
		}

		userData, err := generateUserDataFor(st.PublicIP, nodeId, st.CaCert, st.CaCertPem, st.CaSigner)
		if err != nil {
			fmt.Printf("Error creating new client cert", err)
			return err
		}

		spotReqId, err := RequestSpot(st.Ec2, amiId, instType, keyId, userData, jobId, maxCph)
		if err != nil {
			fmt.Printf("Error creating new spot request", err)
			return err
		}

		_, err = st.Db.Exec("update magnum_node set spotReqId=? where nodeId=?", spotReqId, nodeId)
		if err != nil {
			return err
		}
	}
	return nil
}

func NodesRunning(db *sql.DB, jobId string) ([]*string, []*string, error) {
	rows, err := db.Query("select instanceId, spotReqId from magnum_node where jobId=?", jobId)

	if err != nil {
		return nil, nil, err
	}

	running := []*string{}
	spotReq := []*string{}

	for rows.Next() {
		var instanceId, spotReqId string
		err = rows.Scan(&instanceId, spotReqId)
		if err != nil {
			return nil, nil, err
		}

		if instanceId != "" {
			running = append(running, &instanceId)
		}
		if spotReqId != "" {
			spotReq = append(spotReq, &spotReqId)
		}
	}

	return running, spotReq, nil
}

func CheckOpenRequests(st* ServerState, openReqs []*string) error {
	// TODO: filter on Magnum-Job tag
	params := &ec2.DescribeSpotInstanceRequestsInput {SpotInstanceRequestIds: openReqs,}

	resp, err := st.Ec2.DescribeSpotInstanceRequests(params)

	if err != nil {
		return err
	}

	for _,req := range(resp.SpotInstanceRequests) {
		if req.InstanceId == nil {
			fmt.Printf("SpotReq %s still unfulfilled", req.SpotInstanceRequestId)
			continue
		}

		/*
		if req.Status == {

		}*/

	}

	return nil
}


func EvalJobs(st *ServerState) error {
	rows, err := st.Db.Query("select jobId, memo, cph, started, ended from magnum_job")
	if err != nil {
		return err
	}

	for rows.Next() {
		var jobId, memo string
		var cph int
		var started, ended time.Time
		err = rows.Scan(&jobId, &memo, &cph, &started, &ended)
		if err != nil {
			fmt.Printf("Scan failed %s", err)
			return err
		}
		fmt.Printf("Job %s (%s) started %s stopped %s\n", jobId, memo, started, ended)

		runningNow, openReqs, err := NodesRunning(st.Db, jobId)
		if err != nil {
			return err
		}

		if ended.Before(time.Now()) {
			go TerminateInstances(st.Ec2, jobId, runningNow)
			go CancelSpotRequests(st.Ec2, jobId, openReqs)
		} else {
			go CheckOpenRequests(st, openReqs)
			go MaybeRequestInstances(st, jobId, cph, runningNow, openReqs)
		}
	}

	return nil
}


func NewServerState(serverIP, ca_crt, ca_key, aws_creds, aws_user, aws_region, db_file string) (*ServerState, error) {

	db, err := sql.Open("sqlite3", db_file)
	if err != nil {
		return nil, err
	}

	err = initDatabase(db)
	if err != nil {
		return nil, err
	}

	ec2_cfg := &aws.Config {
		Credentials: credentials.NewSharedCredentials(aws_creds, aws_user),
		Region: aws.String(aws_region),
		LogLevel: aws.LogLevel(aws.LogDebug),
	}
	svc := ec2.New(ec2_cfg)

	caCertPem, err := ioutil.ReadFile(ca_crt)
	if err != nil {
		fmt.Printf("Error reading CA certificate file %s\n", ca_crt)
		return nil, err
	}

	caKeyPem, err := ioutil.ReadFile(ca_key)
	if err != nil {
		fmt.Printf("Error reading CA key file %s\n", ca_key)
		return nil, err
	}

	caCreds, err := tls.X509KeyPair(caCertPem, caKeyPem)

	caCert, err := x509.ParseCertificate(caCreds.Certificate[0])
	if err != nil {
		return nil, err
	}

	caKey := caCreds.PrivateKey

	return &ServerState{PublicIP: serverIP,
		Db:db,
		Ec2:svc,
		CaCert: caCert,
		CaCertPem: string(caCertPem),
		CaSigner: caKey}, nil
}

func MagnumServer(srv, serverIP, ca_crt, ca_key, srv_crt, srv_key, aws_creds, aws_user, aws_region, db_file string) {

	st, err := NewServerState(serverIP, ca_crt, ca_key, aws_creds, aws_user, aws_region, db_file)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr: srv,
		TLSConfig: getTlsConfiguration(ca_crt, srv_crt, srv_key),
	}

	// FIXME call on server instead of global mux?
	//http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/blob/", wrapHandler(st.Db, HandleGetBlob))
	http.HandleFunc("/register", wrapHandler(st.Db, HandleNodeStartup))
	//http.HandleFunc("/queue", wrapHandler(st.Db, HandleQueue))
	http.HandleFunc("/status", wrapHandler(st.Db, HandleStatus))
	http.HandleFunc("/result", wrapHandler(st.Db, HandleResult))

	go server.ListenAndServeTLS("", "")

	evalInterval := 60
	tickChan := time.NewTicker(time.Second * time.Duration(evalInterval)).C

	for {
		select {
		case <- tickChan:
			err = EvalJobs(st)
			if err != nil {
				fmt.Printf("EvalJobs failed:", err)
			}
		}
	}

}
