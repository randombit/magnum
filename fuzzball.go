package main

import (
	"archive/tar"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"errors"
	"io/ioutil"
	"log"
	"net/url"
	"net/http"
	"os/exec"
	"path"
	"strconv"
	"time"
	"os"
	"syscall"
	"strings"
	"bufio"
)

type Fuzzer struct {
	FuzzerId string
	Proc *exec.Cmd
	OutputDir string
	StatsFile string
}

type ClientState struct {
	ServerAddr string

	SystemCA *x509.Certificate
	ClientCreds *tls.Certificate // includes client key

	TLSConfig  *tls.Config
	HTTPClient *http.Client

	WorkingDir string
	Fuzzer *Fuzzer
}

/*
In general a process we run takes a set of static inputs which it
grinds on and eventually produces outputs and occasional status
reports (eg, when fuzzer_stats changes)

There can also be additional processes which maybe only produce
stautus reports, for example one every 60s that checks and outputs
uptime as a stat, but produces no job output. Etc.


We have a channel per process being run on the system.

The status reports are [string]string maps

The job outputs are tagged with the type? type="hang|crash|password_found"
Plus a binary? output of some kind

Alternately, afl can just base64 it or whatev
Or store binary in the string?



Handling saturating the machine is tricky, even hardcoding to afl...

Try #0 The afl-fuzzer process checks its own health by examining the
fuzzer_stats before it sends them.  If it notices that the execution
rate is too low it ...?

Try #1: At a random interval (while processing stats, has a if rng %
521 == 0), the afl-fuzzer will while paused run afl-gotcpu. If gotcpu
returns oversubscribed, that fuzzer process logs a message about it
exits instead of resuming. If the channel is closed the main loop
here can detect this??? and handles it by ?!?!?

Try #2: main loop has a another channel which is running the goroutine

 while true {
   exec `afl-gotcpu`
   chan <- $?
   next_try = 5m if oversubscribed else 1m # ???
   sleep(next_try)
  }

if this channel reports oversubscribed, the main loop kills a fuzzer.
If it reports ok, the main loop starts another fuzzer.
It starts by just a single fuzzer plus the gotcpu checker

The gotcpu can follow the same protocol, return
 m["afl-gotcpu"] = [0|1|2] # return code




*/

type WorkOutput struct {
	Type string
	// add timestamp set in NewWorkOutput
	Values map[string]string
}

/*
"stats"
  Freeform values K=V following some convention set by program in question
m["type"] = "afl", "system", "john", ...

"output"

m["type"] = "crash"
  Afl found a crash
m["type"] = "hang"
  Afl found a crash
Values["result"] = Afl input base64
Values["..."] = other values

"sync"

m["type"] = "afl", "john", ????
m["value"] = tar/gzip of whatever



"

*/

func NewWorkOutput(typeStr string) (*WorkOutput) {
	return &WorkOutput{Type:typeStr, Values: make(map[string]string)}
}

func NewWorkOutputSingle(typ, key, val string) (*WorkOutput) {
	wo := NewWorkOutput(typ)
	wo.Values[key] = val
	return wo

}

func runGotCpu(c chan *WorkOutput) {
	nextCheck := time.Duration(1)
	for {
		time.Sleep(nextCheck * time.Second)
		cmd := exec.Command("afl-gotcpu")

		cmd.Start()
		result := cmd.Wait()

		gotcpuResult := 0
		if result != nil {
			gotcpuResult = result.(*exec.ExitError).ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
		}

		log.Print("afl-gotcpu returned", gotcpuResult)
		// Todo do these intervals make sense
		if gotcpuResult == 0 {
			//c <- NewWorkOutputSingle("afl-gotcpu", "worker-count", "+1")
			c <- NewWorkOutputSingle("afl-gotcpu", "worker-count", "0")
			nextCheck = time.Duration(10)
		} else if gotcpuResult == 1 {
			c <- NewWorkOutputSingle("afl-gotcpu", "worker-count", "0")
			nextCheck = time.Duration(20)
		} else if gotcpuResult == 2 {
			// oversubscribed
			c <- NewWorkOutputSingle("afl-gotcpu", "worker-count", "-1")
			nextCheck = time.Duration(30)
		}
		fmt.Printf("gotcpu %d\n", gotcpuResult)
	}
}

func getHostLoadAvg(c chan *WorkOutput) string {

	for {
		contents, err := ioutil.ReadFile("/proc/loadavg")
		if err == nil {
			str_contents := string(contents[:len(contents)])
			args := strings.Split(str_contents, " ")
			m := NewWorkOutput("stat")
			//m.Values["uptime"] = "5 min"
			m.Values["loadavg_0"] = args[0]
			m.Values["loadavg_1"] = args[1]
			m.Values["loadavg_5"] = args[2]
			c <- m
		}
		time.Sleep(60 * time.Second)
	}
}

func getFileModTime(path string) (int64, error) {
	statBuf, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return statBuf.ModTime().Unix(), nil
}

func StartFuzzer(input_binary, input_corpus, workingDir string) (*Fuzzer, error) {
	// TODO: start a single master somewhere?
	fuzzerType := "-S"

	// TODO do this just once
	outDir := fmt.Sprintf("%s/afl_out/", workingDir)
	os.Mkdir(outDir, 0700)

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("Error getting hostname", err)
	}

	// TODO check for conflicts: sugguests fuzzer name collision
	hostId := fmt.Sprintf("%s_%d", hostname, time.Now().Unix())
	//outDir, err = ioutil.TempDir(outDir, hostId + "_")

	log.Printf("Starting afl with input %s output %s fuzzer %s bin %s", input_corpus, outDir, hostId, input_binary)

	// TODO: sandbox/container somehow? Run under new uid?
	// TODO: support for libFuzzer :(
	cmd := exec.Command("afl-fuzz", "-i", input_corpus, "-o", outDir, fuzzerType, hostId, input_binary, "@@")

	// FIXME
	cmd.Env = []string{"AFL_SKIP_CPUFREQ=1"}
	cmd.Dir = workingDir

	cmd.Start()

	outDir = path.Join(outDir, hostId)
	statsFile := path.Join(outDir, "fuzzer_stats")
	return &Fuzzer{FuzzerId:hostId, OutputDir:outDir, StatsFile:statsFile, Proc:cmd}, nil
}

func PauseFuzzer(fuzzer* Fuzzer) error {
	return fuzzer.Proc.Process.Signal(syscall.SIGSTOP)
}

func RestartFuzzer(fuzzer* Fuzzer) error {
	return fuzzer.Proc.Process.Signal(syscall.SIGCONT)
}

func KillFuzzer(fuzzer* Fuzzer) error {
	// Or SIGKILL to be sure?
	return fuzzer.Proc.Process.Signal(syscall.SIGQUIT)
}

func readAflStats(fuzzer *Fuzzer) (map[string]string, error) {
	f, err := os.Open(fuzzer.StatsFile)
	if err != nil {
		log.Fatal(err)
	}
	bf := bufio.NewReader(f)

	vals := make(map[string]string)

	for {
		line, _, err := bf.ReadLine()

		if err == io.EOF {
			break;
		}
		if err != nil {
			return nil, err
		}

		if len(line) == 0 {
			continue;
		}

		parts := strings.Split(string(line), ":")

		if len(parts) != 2 {
			return nil, errors.New(fmt.Sprintf("Bad input line '%s' in file '%s'", line, fuzzer.StatsFile))
		}
		vals[strings.Trim(parts[0], " ")] = strings.Trim(parts[1], " ")
	}
	return vals, nil
}


func runFuzzer(c chan *WorkOutput, state *ClientState, quit chan bool) {

	fuzzerCheckInterval := time.Duration(1)
	queueBackupInterval := 1 * time.Minute

	binaryPath := fmt.Sprintf("%s/target", state.WorkingDir)
	corpusPath := fmt.Sprintf("%s/corpus", state.WorkingDir)

	fuzzer, err := StartFuzzer(binaryPath, corpusPath, state.WorkingDir)
	if err != nil {
		log.Print("Failed to start fuzzer", err)
		return
	}

	time.Sleep(time.Second) // FIXME!

	statsTime, err := getFileModTime(fuzzer.StatsFile)
	if err != nil {
		log.Print("Could not get stats file", fuzzer.StatsFile, err)
		return
	}

	lastQueueBackup := time.Now()

	for {
		curStatsTime, err := getFileModTime(fuzzer.StatsFile)

		if err != nil {
			log.Print("Could not read stats file", fuzzer.StatsFile, " ", err)
		} else if curStatsTime > statsTime {
			log.Printf("Stats file %s has mod time %d last read %d", fuzzer.StatsFile, statsTime, curStatsTime)

			statsTime = curStatsTime
			vals, err := readAflStats(fuzzer)

			if err == nil {
				m := NewWorkOutput("afl-stats")
				m.Values = vals
				c <- m

			} else {
				log.Printf("Failed getting fuzzer stats from %s: %s", fuzzer.StatsFile, err)
			}
		}

		if time.Now().Sub(lastQueueBackup) > queueBackupInterval {
			m := NewWorkOutput("sync")

			queueDir := path.Join(fuzzer.OutputDir, "queue")

			PauseFuzzer(fuzzer)

			queue, err := ioutil.ReadDir(queueDir)

			if err != nil {
				log.Printf("Error reading queue %s: %s", queueDir, err)
			}

			buf := new(bytes.Buffer)
			tw := tar.NewWriter(buf)
			// Not compressed to avoid bombs on the server

			for _, fi := range queue {
				fileName := fi.Name()
				contents, err := ioutil.ReadFile(path.Join(queueDir, fileName))
				if err != nil {
					log.Printf("Error reading queue file", fileName, err)
					continue
				}

				hdr := &tar.Header{Name:fileName, Mode: 0600, Size: int64(len(contents))}
				err = tw.WriteHeader(hdr)
				if err != nil {
					log.Printf("Error writing tar header for file", fileName, err)
					continue
				}

				_, err = tw.Write(contents)
				if err != nil {
					log.Printf("Error writing tar contents for file", fileName, err)
					continue
				}
			}

			RestartFuzzer(fuzzer)

			log.Printf("Wrote %d bytes as queue save fuzzer %s", buf.Len(), fuzzer.FuzzerId)
			m.Values["value"] = base64.StdEncoding.EncodeToString(buf.Bytes())
			c <- m
			lastQueueBackup = time.Now()
		}

		time.Sleep(fuzzerCheckInterval * time.Second)
	}

	m := NewWorkOutput("exit")
	c <- m
}

func getAndSaveBinary(state *ClientState, hashId, writeTo string, binary bool) error {
	resp, err := state.HTTPClient.Get(fmt.Sprintf("%s/blob/%s", state.ServerAddr, hashId))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// TODO Content-Type check
	//fmt.Printf("Type\n", resp.Header["Content-Type"][0])

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	fmt.Printf("Got %d bytes\n", len(contents))

	// FIXME
	var mode os.FileMode = 0600
	if binary {
		mode = 0700
	}
	err = ioutil.WriteFile(writeTo, contents, mode)
	if err != nil {
		return err
	}
	return nil
}

func PostSync(state *ClientState, syncBlob string) (error) {
	resp, err := state.HTTPClient.PostForm(state.ServerAddr + "/sync",
		url.Values{
			"Value": {syncBlob},
		})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Sync failed %d", resp.StatusCode))
	}

	return nil
}

func PostStatus(state *ClientState, running, execs int) (error) {
	resp, err := state.HTTPClient.PostForm(state.ServerAddr + "/status",
		url.Values{
			"FuzzersRunning": {strconv.FormatInt(int64(running), 10)},
			"Executions": {strconv.FormatInt(int64(execs), 10)},
		})

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Status update failed %d", resp.StatusCode))
	}

	return nil
}

func RegisterWithServer(state *ClientState) error {

	// Authentication will be implicit by client auth?
	resp, err := state.HTTPClient.PostForm(state.ServerAddr + "/register",
		url.Values{"NodePublicIP": {"1.2.3.4"},
			"CPUs": {"0"}})

	if err != nil {
		return err
	}
	work, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Login failed %d", resp.StatusCode))
	}

	fmt.Printf("work = %s\n", work)

	// Open the tar archive for reading.
	r := bytes.NewReader(work)
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}


		buf := make([]byte, hdr.Size)
		n, err := tr.Read(buf)
		if int64(n) != hdr.Size {
			log.Fatalln("WTF")
		}

		ioutil.WriteFile(path.Join(state.WorkingDir, hdr.Name), buf, 0600)
	}

	return nil
}

func sumOf(m map[string]int) int {
	s := 0
	for k,v := range(m) {
		fmt.Printf("Execution report fuzzer %s performed %d execs", k, v)
		s += v
	}
	return s
}

func Fuzzball(server, baseDir, userInfo string, statusInterval int) {

	state := &ClientState{ServerAddr:"https://" + server}

	err := loadClientTlsConfiguration(state, userInfo)
	if err != nil {
		log.Fatal("Error setting up TLS", err)
	}
	state.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: state.TLSConfig}}

	workingDir, err := ioutil.TempDir(baseDir, "magnum_")
	if err != nil {
		log.Fatal("Error creating temp dir", err)
	}
	os.Mkdir(path.Join(workingDir, "corpus"), 0700)

	log.Print("Starting fuzzball in", workingDir)
	state.WorkingDir = workingDir

	err = RegisterWithServer(state)
	if err != nil {
		log.Fatal("AutoToServer failed", err)
	}

	outputChan := make(chan *WorkOutput)

	quit := make(chan bool)
	fuzzerQuitChans := []chan bool{}
	fuzzerQuitChans = append(fuzzerQuitChans, quit)

	go runFuzzer(outputChan, state, quit)
	go getHostLoadAvg(outputChan)
	go runGotCpu(outputChan)

	tickChan := time.NewTicker(time.Second * time.Duration(statusInterval)).C

	execRep := make(map[string]int)

	for {
		select {
		case result := <- outputChan:

			if result.Type == "afl-gotcpu" {
				wc := result.Values["worker-count"]
				switch wc {
				case "+1":
					quit := make(chan bool)
					fuzzerQuitChans = append(fuzzerQuitChans, quit)
					go runFuzzer(outputChan, state, quit)
				case "-1":
					// TODO: signal last fuzzer instead of first
					fmt.Println("Signalling a fuzzer to go down")
					fuzzerQuitChans[0] <- true
					fuzzerQuitChans = fuzzerQuitChans[1:]
				}
			} else if result.Type == "afl-stats" {
				e, err := strconv.ParseInt(result.Values["execs_done"], 10, 32)
				if err != nil {
					log.Printf("Invalid integer execs_done %s", result.Values["execs_done"])
				}
				execRep[result.Values["fuzzer_pid"]] = int(e)
			} else if result.Type == "sync" {
				PostSync(state, result.Values["Value"])
			}

		case <- tickChan:
			PostStatus(state, len(fuzzerQuitChans), sumOf(execRep));
		}
	}

}

