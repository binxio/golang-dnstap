/*
 * Copyright (c) 2019 by Farsight Security, Inc.
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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	dnstap "github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// S3Output send dnstap messages a JSON to an S3 bucket.
type S3Output struct {
	keyPrefix    string
	bucketName   string
	compress     bool
	verbose      bool
	flushPeriod  time.Duration
	maxCacheSize int
	s3           *s3.Client
	buffer       *bytes.Buffer
	log          dnstap.Logger
	data         chan []byte
	done         chan struct{}
}

// SetLogger configures a logger for error events in the TextOutput
func (o *S3Output) SetLogger(logger dnstap.Logger) {
	o.log = logger
}

// create a new S3 key to store the buffered messages in
func (o *S3Output) newS3Key() string {
	now := time.Now()
	uuid := newRandBits()
	hostName, _ := os.Hostname()
	suffix := "log"
	if o.compress {
		suffix = "log.gz"
	}
	return fmt.Sprintf("%s/%04d/%02d/%02d/%02d/%04d%02d%02dT%02d%02d%02d.%06dZ-%s-%x.%s",
		o.keyPrefix, now.Year(), now.Month(), now.Day(), now.Hour(), now.Year(), now.Month(), now.Day(),
		now.Hour(), now.Minute(), now.Second(), now.Nanosecond(), hostName, uuid, suffix)
}

// returns a new random byte array of 16 bytes
func newRandBits() []byte {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		logger.Printf("failed to read random generator, %s\n", err)
	}
	return uuid
}

// MyCustomResolver resolves to the environment variable S3_ENDPOINT_URL for the service s3, if set
func MyCustomResolver(service, region string, options ...interface{}) (aws.Endpoint, error) {
	if service == s3.ServiceID {
		url := os.Getenv("S3_ENDPOINT_URL")
		if url != "" {
			return aws.Endpoint{
				PartitionID:   "aws",
				URL:           url,
				SigningRegion: "custom-signing-region",
			}, nil
		}
	}

	return aws.Endpoint{}, &aws.EndpointNotFoundError{}
}

// environmentVariableToBoolean returns the value of the environment variable `name` or `defaultValue` if not set or invalid
func environmentVariableToBoolean(name string, defaultValue bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}
	override, err := strconv.ParseBool(value)
	if err != nil {
		logger.Printf("invalid %s: %s", name, err)
		return defaultValue
	}
	return override
}

// environmentVariableToPositiveInteger returns the value of the environment variable `name` or `defaultValue` if not set or invalid
func environmentVariableToPositiveInteger(name string, defaultValue int) int {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}
	override, err := strconv.ParseInt(value, 10, 32)
	if err != nil || override <= 0 {
		if err != nil {
			logger.Printf("invalid %s: %s", name, err)
		} else {
			logger.Printf("invalid %s: not a positive integer", name)
		}
		return defaultValue
	}
	return int(override)
}

// environmentVariableToDuration returns the value of the environment variable `name` or `defaultValue` if not set or invalid
func environmentVariableToDuration(name string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return defaultValue
	}
	override, err := time.ParseDuration(value)
	if err != nil {
		logger.Printf("invalid %s: %s", name, err)
		return defaultValue
	}
	return override
}

// newS3Output creates a new dnstap output writer which writes dnstap messages as
// json to the bucket `bucketName`.
// configurable through the following environment variables:
// DNSTAP_S3_BUCKET_REGION  - bucket region, no default
// DNSTAP_S3_KEY_PREFIX  - prefix for the objects, default DNSlogs
// DNSTAP_S3_USE_PATH_STYLE - whether to use the path style s3 api calls, default false
// DNSTAP_S3_COMPRESS - whether to compress the json objects on the bucket, default false
// DNSTAP_S3_VERBOSE - whether to produce verbose output, default false
// DNSTAP_S3_MAX_CACHE_SIZE - max cache size in bytes, defaults to 128 * 1024 * 1024
// DNSTAP_S3_FLUSH_PERIOD - flush period of the buffer, default to 30s
func newS3Output(ctx context.Context, bucketName string) (*S3Output, error) {

	keyPrefix := "DNSLogs"
	if keyPrefixOverride := os.Getenv("DNSTAP_S3_KEY_PREFIX"); keyPrefixOverride != "" {
		keyPrefix = keyPrefixOverride
	}

	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(MyCustomResolver)),
	)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if region := os.Getenv("DNSTAP_S3_BUCKET_REGION"); region != "" {
			o.Region = region
		}
		o.UsePathStyle = environmentVariableToBoolean("DNSTAP_S3_USE_PATH_STYLE", false)
	})

	// make sure the bucket exists
	_, err = client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: &bucketName})
	if err != nil {
		return nil, err
	}

	return &S3Output{
		bucketName:   bucketName,
		keyPrefix:    keyPrefix,
		s3:           client,
		compress:     environmentVariableToBoolean("DNSTAP_S3_COMPRESS", false),
		verbose:      environmentVariableToBoolean("DNSTAP_S3_VERBOSE", false),
		maxCacheSize: environmentVariableToPositiveInteger("DNSTAP_S3_MAX_CACHE_SIZE", 128*1024*1024),
		flushPeriod:  environmentVariableToDuration("DNSTAP_S3_FLUSH_PERIOD", time.Second*30),
		log:          logger,
		buffer:       new(bytes.Buffer),
		data:         make(chan []byte, outputChannelSize),
		done:         make(chan struct{}),
	}, nil
}

// GetOutputChannel returns the channel to output incoming dnstap messages
func (o *S3Output) GetOutputChannel() chan []byte {
	return o.data
}

// Close flush buffer and close output
func (o *S3Output) Close() {
	o.flush()
	close(o.data)
	<-o.done
}

func (o *S3Output) flush() {
	if o.buffer.Len() == 0 {
		return
	}

	key := o.newS3Key()
	body := bytes.NewReader(o.buffer.Bytes())
	contentEncoding := aws.String("utf-8")
	contentType := aws.String("plain/text")

	if o.compress {
		var result bytes.Buffer
		compressor := gzip.NewWriter(&result)
		if _, err := compressor.Write(o.buffer.Bytes()); err != nil {
			o.log.Printf("%s\n", err)
			os.Exit(1)
		}
		if err := compressor.Close(); err != nil {
			o.log.Printf("%s\n", err)
			os.Exit(1)
		}
		body = bytes.NewReader(result.Bytes())
		contentType = aws.String("application/gzip")
		contentEncoding = aws.String("gzip")
	}
	if o.verbose {
		o.log.Printf("writing buffer of %d bytes to %s\n", body.Len(), key)
	}

	request := s3.PutObjectInput{
		Bucket:          &o.bucketName,
		Body:            body,
		Key:             aws.String(key),
		ContentEncoding: contentEncoding,
		ContentType:     contentType,
	}

	_, err := o.s3.PutObject(context.Background(), &request)
	if err != nil {
		o.log.Printf("failed to put object to bucket, %s", err)
		os.Exit(1)
	}
	o.buffer.Reset()
}

// RunOutputLoop writes dnstap messages to the s3 bucket
func (o *S3Output) RunOutputLoop() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	signal.Notify(signals, os.Interrupt, syscall.SIGINT)
	ticker := time.NewTicker(o.flushPeriod)

	defer func() {
		o.log.Printf("closing S3 output")
		ticker.Stop()
		o.Close()
		close(o.done)
	}()
	for {
		select {
		case frame, ok := <-o.data:
			if !ok {
				return
			}
			message := dnstap.Dnstap{}
			if err := proto.Unmarshal(frame, &message); err != nil {
				o.log.Printf("dnstap.s3: proto.Unmarshal() failed: %s\n", err)
				break
			}
			json, ok := dnstap.JSONFormat(&message)
			if !ok {
				o.log.Printf("dnstap.s3: text format function failed\n")
				break
			}
			if _, err := o.buffer.Write(json); err != nil {
				o.log.Printf("dnstap.s3: write error: %v, returning\n", err)
				break
			}
			if o.buffer.Len() > o.maxCacheSize {
				o.flush()
			}

		case <-ticker.C:
			o.flush()

		case signal := <-signals:
			o.log.Printf("dnstap.s3 received signal %v\n", signal)
			o.flush()
			close(signals)
			// This is not as it is supposed to be, but as it is done in fileoutput.
			// the signal should be caught by the main loop.
			os.Exit(1)
			return
		}
	}
}

func addS3Outputs(mo *mirrorOutput, buckets stringList) error {
	for _, bucket := range buckets {

		output, err := newS3Output(context.Background(), bucket)
		if err != nil {
			return err
		}
		go output.RunOutputLoop()
		mo.Add(output)
	}
	return nil
}
