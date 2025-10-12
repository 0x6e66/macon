# macon (Malware Corpus Normalizer)

## Description

The problem with many popular malware corpora like [Virustotal](https://virustotal.com) or
[Triage](https://tria.ge/) is that the samples for a specific family are very heterogeneous.
There are different file types from different stages of the malware all placed under one label.

This project aims to tackle this issue. To normalize a malware corpus a graph structure is used.
In this graph every distinct sample is a node. If a sample drops another sample, the dropped sample
is connected via an edge. The dropped sample could be the result of a regular dropper or something 
like the native code of a android apk (`lib/*/*.so`). Inside the graph every malware sample is
guaranteed to be deduplicated. 

## Installation

- From git
  ```bash
  cargo install --git https://github.com/0x6e66/macon
  ```
