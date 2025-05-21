# pcapJoin

A high-performance tool for joining multiple PCAP/PCAPNG files into a single chronologically ordered capture file.

## Overview

pcapJoin takes multiple packet capture files (PCAP/PCAPNG) and combines them into a single output file, preserving the correct chronological order of packets based on their timestamps. This is particularly useful for:

- Merging captures from multiple network interfaces or capture points
- Combining fragmented captures (e.g., split by time or size limits)
- Creating a unified view of network traffic across different sources
- Post-processing distributed capture systems

## Features

- **Timestamp-based ordering**: Ensures packets are properly sequenced in chronological order
- **Format support**: Works with PCAP, PCAPNG, and gzipped capture files
- **Performance optimized**: Multi-threaded processing with two processing modes:
  - Direct mode: Faster processing for smaller files
  - Chunked mode: Memory-efficient processing for large files
- **Automatic mode selection**: Chooses the optimal processing strategy based on file size
- **Progress reporting**: Provides detailed feedback during processing

## Installation

### Prerequisites

- Go 1.17 or later
- libpcap development libraries:
  - Ubuntu/Debian: `sudo apt-get install libpcap-dev`
  - Red Hat/Fedora: `sudo dnf install libpcap-devel`
  - macOS: Included with Xcode command line tools or `brew install libpcap`
  - Windows: [Npcap](https://nmap.org/npcap/) with SDK

### Building from Source

1. Clone the repository or download the source code
2. Install the required Go packages:
   ```
   go mod init github.com/voicetel/pcapJoin
   go mod tidy
   ```
3. Build the executable:
   ```
   go build pcapJoin.go
   ```

## Usage

Basic usage:

```
./pcapJoin [options] file1.pcap file2.pcap [file3.pcap ...]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-o filename` | Output file name (default: "joined.pcap") |
| `-v` | Verbose mode: display detailed processing information |
| `-workers n` | Number of worker goroutines (0 = use all CPU cores) |
| `-chunked` | Force chunked mode for low memory usage |
| `-direct` | Force direct mode for faster processing |

### Examples

Join two PCAP files with default settings:
```
./pcapJoin capture1.pcap capture2.pcap
```

Join multiple PCAP files with verbose output and a custom output filename:
```
./pcapJoin -v -o combined.pcap cap1.pcap cap2.pcap cap3.pcap
```

Process large files with memory-efficient mode:
```
./pcapJoin -chunked -o large_combined.pcap large_file1.pcap large_file2.pcap
```

Join compressed captures:
```
./pcapJoin capture1.pcap.gz capture2.pcap.gz -o uncompressed.pcap
```

## How It Works

pcapJoin processes the input files in parallel using multiple worker threads:

1. The tool reads packets from all input files concurrently
2. Each packet is timestamped and placed into a priority queue
3. Packets are extracted from the queue in timestamp order (earliest first)
4. Ordered packets are written to the output file

The tool offers two processing modes that are selected automatically based on file size:

- **Direct mode**: Loads all packets into memory for faster processing (best for files <1M packets)
- **Chunked mode**: Processes packets in batches to reduce memory usage (best for large files)

## Performance Considerations

- For optimal performance, the number of worker threads is set to use all available CPU cores by default
- Use `-direct` mode for faster processing when memory is not a constraint
- Use `-chunked` mode when working with very large capture files to reduce memory usage
- Compressed files are automatically uncompressed to temporary files during processing

## Limitations

- The tool currently preserves packet ordering based on timestamps but does not modify timestamps
- For very large files (>10GB), sufficient disk space is needed for temporary uncompressed files
- When joining files with different link types, the output uses the link type of the first file

## 🙌 Contributors

We welcome, acknowlege, and appreciate contributors. Thanks to these awesome people for making this project possible:

[Michael Mavroudis](https://github.com/mavroudis)

## 💖 Sponsors

We gratefully acknowledge the support of our amazing sponsors:

| Sponsor | Contribution |
|---------|--------------|
| [VoiceTel Communications](http://www.voicetel.com) | Everything :) |

## License

This software is provided under the [MIT License](LICENSE).

## Acknowledgments

- Based on libraries from the [gopacket](https://github.com/google/gopacket) project
- Inspired by the design of [pcapSearch](https://github.com/voicetel/pcapSearch)
