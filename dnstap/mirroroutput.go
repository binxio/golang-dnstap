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
	dnstap "github.com/dnstap/golang-dnstap"
	"sync"
)

type mirrorOutput struct {
	outputs   []dnstap.Output
	data      chan []byte
	done      chan struct{}
	waitGroup sync.WaitGroup
}

func newMirrorOutput() *mirrorOutput {
	return &mirrorOutput{
		data: make(chan []byte, outputChannelSize),
		done: make(chan struct{}),
	}
}

func (mo *mirrorOutput) Flush() {
	for _, output := range mo.outputs {
		output.Flush()
	}
}

func (mo *mirrorOutput) Add(o dnstap.Output) {
	mo.waitGroup.Add(1)
	go func() {
		o.RunOutputLoop()
		mo.waitGroup.Done()
	}()
	mo.outputs = append(mo.outputs, o)
}

// RunOutputLoop copies all dnstap messages into the all the channel of each of the output tqps.
// it stops when the input data channel is closed.
func (mo *mirrorOutput) RunOutputLoop() {
	defer func() {
		for _, o := range mo.outputs {
			o.Close()
		}
	}()

	for {
		select {
		case b, ok := <-mo.data:
			if !ok {
				return
			}
			for _, o := range mo.outputs {
				o.GetOutputChannel() <- b
			}
		case <-mo.done:
			return
		}
	}
}

func (mo *mirrorOutput) Close() {
	mo.done <- struct{}{}
	close(mo.done)
	close(mo.data)
	mo.waitGroup.Wait()
}

func (mo *mirrorOutput) GetOutputChannel() chan []byte {
	return mo.data
}
