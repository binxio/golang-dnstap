/*
 * Copyright (c) 2013-2019 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"flag"
	"fmt"
	"github.com/dnstap/golang-dnstap"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

type stringList []string

func (sl *stringList) Set(s string) error {
	*sl = append(*sl, s)
	return nil
}
func (sl *stringList) String() string {
	return strings.Join(*sl, ", ")
}

var (
	flagTimeout    = flag.Duration("t", 0, "I/O timeout for tcp/ip and unix domain sockets")
	flagWriteFile  = flag.String("w", "", "write output to file")
	flagAppendFile = flag.Bool("a", false, "append to the given file, do not overwrite. valid only when outputting a text or YAML file.")
	flagQuietText  = flag.Bool("q", false, "use quiet text output")
	flagYamlText   = flag.Bool("y", false, "use verbose YAML output")
	flagJSONText   = flag.Bool("j", false, "use verbose JSON output")
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]...\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Quiet text output format mnemonics:
    AQ: AUTH_QUERY
    AR: AUTH_RESPONSE
    RQ: RESOLVER_QUERY
    RR: RESOLVER_RESPONSE
    CQ: CLIENT_QUERY
    CR: CLIENT_RESPONSE
    FQ: FORWARDER_QUERY
    FR: FORWARDER_RESPONSE
    SQ: STUB_QUERY
    SR: STUB_RESPONSE
    TQ: TOOL_QUERY
    TR: TOOL_RESPONSE
`)
}

var logger = log.New(os.Stderr, "", log.LstdFlags)

func main() {
	var tcpOutputs, unixOutputs, s3Outputs stringList
	var fileInputs, tcpInputs, unixInputs stringList
	allSocketInputs := make([]*dnstap.FrameStreamSockInput, 0)

	flag.Var(&tcpOutputs, "T", "write dnstap payloads to tcp/ip address")
	flag.Var(&unixOutputs, "U", "write dnstap payloads to unix socket")
	flag.Var(&s3Outputs, "S", "write dnstap payloads to AWS S3 bucket")
	flag.Var(&fileInputs, "r", "read dnstap payloads from file")
	flag.Var(&tcpInputs, "l", "read dnstap payloads from tcp/ip")
	flag.Var(&unixInputs, "u", "read dnstap payloads from unix socket")

	runtime.GOMAXPROCS(runtime.NumCPU())
	log.SetFlags(0)
	flag.Usage = usage

	// Handle command-line arguments.
	flag.Parse()

	if len(fileInputs)+len(unixInputs)+len(tcpInputs) == 0 {
		fmt.Fprintf(os.Stderr, "dnstap: Error: no inputs specified.\n")
		os.Exit(1)
	}

	haveFormat := false
	for _, f := range []bool{*flagQuietText, *flagYamlText, *flagJSONText} {
		if haveFormat && f {
			fmt.Fprintf(os.Stderr, "dnstap: Error: specify at most one of -q, -y, or -j.\n")
			os.Exit(1)
		}
		haveFormat = haveFormat || f
	}

	output := newMirrorOutput()
	if err := addSockOutputs(output, "tcp", tcpOutputs); err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: TCP error: %v\n", err)
		os.Exit(1)
	}
	if err := addSockOutputs(output, "unix", unixOutputs); err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: Unix socket error: %v\n", err)
		os.Exit(1)
	}
	if err := addS3Outputs(output, s3Outputs); err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: s3 outputs error: %v\n", err)
		os.Exit(1)
	}

	if *flagWriteFile != "" || len(tcpOutputs)+len(unixOutputs)+len(s3Outputs) == 0 {
		var format dnstap.TextFormatFunc

		switch {
		case *flagYamlText:
			format = dnstap.YamlFormat
		case *flagQuietText:
			format = dnstap.TextFormat
		case *flagJSONText:
			format = dnstap.JSONFormat
		}

		o, err := newFileOutput(*flagWriteFile, format, *flagAppendFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: File output error on '%s': %v\n",
				*flagWriteFile, err)
			os.Exit(1)
		}
		output.Add(o)
	}

	go output.RunOutputLoop()

	var iwg sync.WaitGroup
	// Open the input and start the input loop.
	for _, fname := range fileInputs {
		i, err := dnstap.NewFrameStreamInputFromFilename(fname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file %s: %v\n", fname, err)
			os.Exit(1)
		}
		i.SetLogger(logger)
		fmt.Fprintf(os.Stderr, "dnstap: opened input file %s\n", fname)
		iwg.Add(1)
		go runInput(i, output, &iwg)
	}
	for _, path := range unixInputs {
		i, err := dnstap.NewFrameStreamSockInputFromPath(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to open input socket %s: %v\n", path, err)
			os.Exit(1)
		}
		i.SetTimeout(*flagTimeout)
		i.SetLogger(logger)
		allSocketInputs = append(allSocketInputs, i)
		fmt.Fprintf(os.Stderr, "dnstap: opened input socket %s\n", path)
		iwg.Add(1)
		go runInput(i, output, &iwg)
	}
	for _, addr := range tcpInputs {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dnstap: Failed to listen on %s: %v\n", addr, err)
			os.Exit(1)
		}
		i := dnstap.NewFrameStreamSockInput(l)
		i.SetTimeout(*flagTimeout)
		i.SetLogger(logger)
		allSocketInputs = append(allSocketInputs, i)
		iwg.Add(1)
		go runInput(i, output, &iwg)
	}

	go func() {
		signals := make(chan os.Signal, 5)
		signal.Notify(signals, os.Interrupt)
		signal.Notify(signals, syscall.SIGINT)
		signal.Notify(signals, syscall.SIGTERM)
		signal.Notify(signals, syscall.SIGHUP)
		for s := range signals {
			if s == syscall.SIGHUP {
				output.Flush()
			} else {
				for _, v := range allSocketInputs {
					v.Close()
				}
				close(signals)
			}
		}
	}()

	iwg.Wait()
	output.Close()
}

func runInput(i dnstap.Input, o dnstap.Output, wg *sync.WaitGroup) {
	go i.ReadInto(o.GetOutputChannel())
	i.Wait()
	wg.Done()
}

func addSockOutputs(mo *mirrorOutput, network string, addrs stringList) error {
	var naddr net.Addr
	var err error
	for _, addr := range addrs {
		switch network {
		case "tcp":
			naddr, err = net.ResolveTCPAddr(network, addr)
		case "unix":
			naddr, err = net.ResolveUnixAddr(network, addr)
		default:
			return fmt.Errorf("invalid network '%s'", network)
		}
		if err != nil {
			return err
		}

		o, err := dnstap.NewFrameStreamSockOutput(naddr)
		if err != nil {
			return err
		}
		o.SetTimeout(*flagTimeout)
		o.SetLogger(logger)
		mo.Add(o)
	}
	return nil
}
