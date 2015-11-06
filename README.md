# SeedCSISMP

A Campus Student Information Sync Management Protocol implementation for Seed Cup.

## How To Build

```bash

cmake .
make
./bin/SeedCup

```

## How It Works

  * SeedCommandCenter
    * SeedSession
      * SeedPacket

## TODO

  * ACK and RJT Packet.
  * SYNC Packet.
  * More complex test cases.
  * Release completed/aborted SeedSession.
    * Release SeedPacket in SeedSession.

## How To Test

As the CSISMP is working at Data Link Layer, aka. Layer 2, we need `libpcap` to send/receive Layer 2 datagrams.

Because the official test case is quite simple, we need to create legal test cases to push further.

My method is:

  * Load the `.pcap` file into WireShark.
  * Save it as `K12 text file`.
  * Manually edit it.
  * Reopen in WireShark.
  * Save it as `.pcap`.
  * Replay it using `tcpreplay`.

## The MIT License

Copyright © 2015 evshiron

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.