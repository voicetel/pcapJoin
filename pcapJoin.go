package main

import (
	"compress/gzip"
	"container/heap"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// Constants for performance tuning
const (
	DefaultWorkers   = 0 // 0 means use GOMAXPROCS
	BatchSize        = 1000
	MaxQueueSize     = 100000
	ChunkThreshold   = 1000000 // Number of packets to consider a file "large"
	ProgressInterval = 10000   // How often to report progress (in packets)
)

// Global verbose flag
var verbose bool

// PacketItem represents a packet with its metadata for the priority queue
type PacketItem struct {
	ci        gopacket.CaptureInfo
	data      []byte
	timestamp time.Time
	sourceID  int // Which input file this came from
}

// PriorityQueue implementation for ordering packets by timestamp
type PriorityQueue []*PacketItem

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	// We want the earliest timestamp at the top of the queue
	return pq[i].timestamp.Before(pq[j].timestamp)
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*PacketItem)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil // avoid memory leak
	*pq = old[0 : n-1]
	return item
}

// logVerbose prints a message only when verbose mode is enabled
func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf(format, args...)
	}
}

// detectFileFormat detects the format of a capture file
func detectFileFormat(filename string) string {
	// Check if the file is gzipped
	if strings.HasSuffix(strings.ToLower(filename), ".gz") {
		baseName := strings.TrimSuffix(strings.ToLower(filename), ".gz")
		if strings.HasSuffix(baseName, ".pcapng") {
			return "pcapng.gz"
		} else if strings.HasSuffix(baseName, ".pcap") {
			return "pcap.gz"
		} else {
			return "unknown.gz"
		}
	}

	// Check file signature for non-gzipped files
	isPcapNG, err := isPcapNGFile(filename)
	if err == nil && isPcapNG {
		return "pcapng"
	}

	// Default to pcap or determine by extension
	if strings.HasSuffix(strings.ToLower(filename), ".pcapng") {
		return "pcapng"
	} else if strings.HasSuffix(strings.ToLower(filename), ".pcap") {
		return "pcap"
	}

	return "unknown"
}

// isPcapNGFile checks if the file is a PCAPNG format file based on the signature
func isPcapNGFile(filename string) (bool, error) {
	// PCAPNG format signature: 0x0A0D0D0A (Block Type: Section Header Block)
	file, err := os.Open(filename)
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Read first 4 bytes to check signature
	signature := make([]byte, 4)
	n, err := file.Read(signature)
	if err != nil || n < 4 {
		return false, err
	}

	// Check for PCAPNG signature (0x0A0D0D0A)
	return signature[0] == 0x0A && signature[1] == 0x0D && signature[2] == 0x0D && signature[3] == 0x0A, nil
}

// openPcapFile opens a PCAP or PCAPNG file and returns a packet source
func openPcapFile(filename string) (*pcap.Handle, error) {
	// Check if file is PCAPNG format
	isPcapNG, err := isPcapNGFile(filename)
	if err != nil {
		// If we can't determine the format, try to open it anyway
		logVerbose("Could not determine if file is PCAPNG format: %v\n", err)
	} else if isPcapNG {
		logVerbose("Detected PCAPNG format file\n")
		// libpcap 1.5.0 and later support PCAPNG format directly
	} else {
		logVerbose("Detected legacy PCAP format file\n")
	}

	// Open the file using libpcap/gopacket
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening capture file: %v", err)
	}

	return handle, nil
}

// uncompressGzipFile takes a gzip file path and returns the path to a temporary
// uncompressed file. The caller is responsible for removing the temporary file.
func uncompressGzipFile(gzipFilePath string) (string, error) {
	// Open the gzip file
	gzipFile, err := os.Open(gzipFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open gzip file: %v", err)
	}
	defer gzipFile.Close()

	// Create a gzip reader
	gzipReader, err := gzip.NewReader(gzipFile)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzipReader.Close()

	// Create a temporary file to hold the uncompressed data
	// We'll use the original filename without the .gz extension if possible
	baseFilename := filepath.Base(gzipFilePath)
	if strings.HasSuffix(baseFilename, ".gz") {
		baseFilename = strings.TrimSuffix(baseFilename, ".gz")
	}

	tempFile, err := os.CreateTemp("", "uncompressed-"+baseFilename)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %v", err)
	}
	defer tempFile.Close()

	// Get the initial size to calculate compression ratio
	initialSize := 0
	if verbose {
		fileInfo, err := gzipFile.Stat()
		if err == nil {
			initialSize = int(fileInfo.Size())
		}
	}

	// Copy the uncompressed data to the temporary file
	written, err := io.Copy(tempFile, gzipReader)
	if err != nil {
		// Clean up the temp file if we encounter an error
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("failed to uncompress data: %v", err)
	}

	if verbose {
		if initialSize > 0 {
			ratio := float64(written) / float64(initialSize)
			fmt.Printf("Uncompressed %s: %.2f MB compressed to %.2f MB (%.1fx ratio)\n",
				gzipFilePath, float64(initialSize)/(1024*1024), float64(written)/(1024*1024), ratio)
		} else {
			fmt.Printf("Successfully uncompressed %s to temporary file (%.2f MB)\n",
				gzipFilePath, float64(written)/(1024*1024))
		}
	}

	return tempFile.Name(), nil
}

// countPacketsInFile counts the total number of packets in a pcap file
func countPacketsInFile(filename string) (int, error) {
	handle, err := openPcapFile(filename)
	if err != nil {
		return 0, err
	}
	defer handle.Close()

	// Fast packet counting
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	var count int
	for range packetSource.Packets() {
		count++
	}

	return count, nil
}

// processFileDirectly reads packets from a file and writes them directly to the priority queue
func processFileDirectly(filename string, sourceID int, pq *PriorityQueue, pqMutex *sync.Mutex, wg *sync.WaitGroup) error {
	defer wg.Done()

	var pcapPath string
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")
	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		pcapPath, err = uncompressGzipFile(filename)
		if err != nil {
			return fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(pcapPath) // Clean up the temporary file when done
	} else {
		pcapPath = filename
	}

	// Open the pcap file
	handle, err := openPcapFile(pcapPath)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Count total packets for progress reporting
	var totalPackets int
	if verbose {
		totalPackets, _ = countPacketsInFile(pcapPath)
		fmt.Printf("File %s contains %d packets\n", filename, totalPackets)
	}

	// Read all packets and add them to the priority queue
	packetCount := 0
	lastProgressUpdate := time.Now()

	for packet := range packetSource.Packets() {
		// Create a PacketItem for the priority queue
		item := &PacketItem{
			ci:        packet.Metadata().CaptureInfo,
			data:      packet.Data(),
			timestamp: packet.Metadata().Timestamp,
			sourceID:  sourceID,
		}

		// Add to priority queue with mutex protection
		pqMutex.Lock()
		heap.Push(pq, item)
		pqMutex.Unlock()

		packetCount++

		// Report progress periodically
		if verbose && (packetCount%ProgressInterval == 0 || time.Since(lastProgressUpdate) > 5*time.Second) {
			if totalPackets > 0 {
				fmt.Printf("File %s: processed %d/%d packets (%.1f%%)\n",
					filename, packetCount, totalPackets, float64(packetCount)/float64(totalPackets)*100)
			} else {
				fmt.Printf("File %s: processed %d packets\n", filename, packetCount)
			}
			lastProgressUpdate = time.Now()
		}
	}

	if verbose {
		fmt.Printf("Completed reading file %s: %d packets\n", filename, packetCount)
	}

	return nil
}

// processPcapFilesChunked processes a pcap file in chunks to minimize memory usage
func processFileChunked(filename string, sourceID int, outputChan chan<- *PacketItem, wg *sync.WaitGroup) error {
	defer wg.Done()

	var pcapPath string
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")
	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		pcapPath, err = uncompressGzipFile(filename)
		if err != nil {
			return fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(pcapPath) // Clean up the temporary file when done
	} else {
		pcapPath = filename
	}

	// Open the pcap file
	handle, err := openPcapFile(pcapPath)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Count total packets for progress reporting
	var totalPackets int
	if verbose {
		totalPackets, _ = countPacketsInFile(pcapPath)
		fmt.Printf("File %s contains %d packets\n", filename, totalPackets)
	}

	// Read all packets and send to output channel
	packetCount := 0
	lastProgressUpdate := time.Now()

	for packet := range packetSource.Packets() {
		// Create a PacketItem for the channel
		item := &PacketItem{
			ci:        packet.Metadata().CaptureInfo,
			data:      packet.Data(),
			timestamp: packet.Metadata().Timestamp,
			sourceID:  sourceID,
		}

		// Send to output channel
		outputChan <- item

		packetCount++

		// Report progress periodically
		if verbose && (packetCount%ProgressInterval == 0 || time.Since(lastProgressUpdate) > 5*time.Second) {
			if totalPackets > 0 {
				fmt.Printf("File %s: processed %d/%d packets (%.1f%%)\n",
					filename, packetCount, totalPackets, float64(packetCount)/float64(totalPackets)*100)
			} else {
				fmt.Printf("File %s: processed %d packets\n", filename, packetCount)
			}
			lastProgressUpdate = time.Now()
		}
	}

	if verbose {
		fmt.Printf("Completed reading file %s: %d packets\n", filename, packetCount)
	}

	return nil
}

// joinPcapFiles joins multiple pcap files into one, preserving packet order by timestamp
func joinPcapFiles(inputFiles []string, outputFile string, forceChunkedMode bool, forceDirectMode bool) error {
	if len(inputFiles) == 0 {
		return fmt.Errorf("no input files specified")
	}

	if len(inputFiles) == 1 {
		// Special case: just copy the file
		logVerbose("Only one input file specified. Creating a copy at %s\n", outputFile)
		return copyPcapFile(inputFiles[0], outputFile)
	}

	// Count total packets in all files for progress estimation
	var totalPackets int
	if verbose {
		fmt.Println("Counting packets in all input files...")
		for _, file := range inputFiles {
			count, err := countPacketsInFile(file)
			if err != nil {
				fmt.Printf("Warning: Could not count packets in %s: %v\n", file, err)
			} else {
				totalPackets += count
				fmt.Printf("  %s: %d packets\n", file, count)
			}
		}
		fmt.Printf("Total packets to process: %d\n", totalPackets)
	}

	// Determine whether to use chunked mode based on total packet count
	useChunkedMode := totalPackets > ChunkThreshold

	// Allow command line flags to override automatic mode selection
	if forceChunkedMode {
		useChunkedMode = true
	} else if forceDirectMode {
		useChunkedMode = false
	}

	if verbose {
		if useChunkedMode {
			fmt.Println("Using chunked mode for large files")
		} else {
			fmt.Println("Using direct mode for processing")
		}
	}

	// Create output file
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer f.Close()

	// Create a pcap writer
	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("error writing pcap header: %v", err)
	}

	if useChunkedMode {
		// Use chunked mode with channels
		return joinPcapFilesChunked(inputFiles, writer, totalPackets)
	} else {
		// Use direct mode with priority queue
		return joinPcapFilesDirect(inputFiles, writer, totalPackets)
	}
}

// copyPcapFile copies a single pcap file to the output
func copyPcapFile(inputFile, outputFile string) error {
	var pcapPath string
	var err error

	// Check if the file is compressed with gzip
	isCompressed := strings.HasSuffix(strings.ToLower(inputFile), ".gz")
	if isCompressed {
		// Create a temporary file to hold the uncompressed data
		pcapPath, err = uncompressGzipFile(inputFile)
		if err != nil {
			return fmt.Errorf("error uncompressing gzip file: %v", err)
		}
		defer os.Remove(pcapPath) // Clean up the temporary file when done
	} else {
		pcapPath = inputFile
	}

	// Open the input pcap file
	handle, err := openPcapFile(pcapPath)
	if err != nil {
		return fmt.Errorf("error opening pcap file: %v", err)
	}
	defer handle.Close()

	// Create the output file
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("error creating output file: %v", err)
	}
	defer f.Close()

	// Create a pcap writer
	writer := pcapgo.NewWriter(f)
	err = writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
	if err != nil {
		return fmt.Errorf("error writing pcap header: %v", err)
	}

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	// Read all packets and write to output
	packetCount := 0
	for packet := range packetSource.Packets() {
		err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			return fmt.Errorf("error writing packet: %v", err)
		}
		packetCount++

		// Report progress periodically
		if verbose && packetCount%10000 == 0 {
			fmt.Printf("Copied %d packets\r", packetCount)
		}
	}

	if verbose {
		fmt.Printf("\nCompleted copying %d packets\n", packetCount)
	}

	return nil
}

// joinPcapFilesDirect joins pcap files using a priority queue approach
func joinPcapFilesDirect(inputFiles []string, writer *pcapgo.Writer, totalPackets int) error {
	// Create a channel to collect packets from all files
	packetChan := make(chan *PacketItem, BatchSize*2)

	// Use a wait group to track when all files have been processed
	var wg sync.WaitGroup
	wg.Add(len(inputFiles))

	// Start reading from each file in parallel
	for i, file := range inputFiles {
		go func(idx int, filename string) {
			defer wg.Done()

			var pcapPath string
			var err error

			// Check if the file is compressed with gzip
			isCompressed := strings.HasSuffix(strings.ToLower(filename), ".gz")
			if isCompressed {
				pcapPath, err = uncompressGzipFile(filename)
				if err != nil {
					fmt.Printf("Error uncompressing %s: %v\n", filename, err)
					return
				}
				defer os.Remove(pcapPath)
			} else {
				pcapPath = filename
			}

			// Open the file
			handle, err := openPcapFile(pcapPath)
			if err != nil {
				fmt.Printf("Error opening %s: %v\n", filename, err)
				return
			}
			defer handle.Close()

			// Create packet source
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetSource.DecodeOptions.Lazy = true
			packetSource.DecodeOptions.NoCopy = true

			// Process each packet
			count := 0
			for packet := range packetSource.Packets() {
				packetChan <- &PacketItem{
					ci:        packet.Metadata().CaptureInfo,
					data:      packet.Data(),
					timestamp: packet.Metadata().Timestamp,
					sourceID:  idx,
				}
				count++
			}

			if verbose {
				fmt.Printf("Completed reading file %s: %d packets\n", filename, count)
			}
		}(i, file)
	}

	// Close the packet channel when all files are processed
	go func() {
		wg.Wait()
		close(packetChan)
	}()

	// Create a priority queue to sort packets by timestamp
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// Process packets from the channel
	var processedCount int
	lastProgressUpdate := time.Now()

	// First, fill the priority queue with initial packets
	for packet := range packetChan {
		heap.Push(&pq, packet)

		// Once we have a good number of packets, start processing
		if pq.Len() >= BatchSize {
			break
		}
	}

	// Now process the queue while continuing to read from the channel
	for {
		// Process a packet from the queue if available
		for pq.Len() > 0 {
			// Get the earliest packet
			item := heap.Pop(&pq).(*PacketItem)

			// Write to output
			err := writer.WritePacket(item.ci, item.data)
			if err != nil {
				return fmt.Errorf("error writing packet: %v", err)
			}

			processedCount++

			// Report progress periodically
			if verbose && (processedCount%ProgressInterval == 0 || time.Since(lastProgressUpdate) > 5*time.Second) {
				if totalPackets > 0 {
					fmt.Printf("Progress: %d/%d packets (%.1f%%)\n",
						processedCount, totalPackets, float64(processedCount)/float64(totalPackets)*100)
				} else {
					fmt.Printf("Progress: %d packets\n", processedCount)
				}
				lastProgressUpdate = time.Now()
			}
		}

		// Get more packets from the channel
		packet, more := <-packetChan
		if !more {
			// No more packets, we're done
			break
		}

		// Add to queue
		heap.Push(&pq, packet)
	}

	// Process any remaining packets in the queue
	for pq.Len() > 0 {
		item := heap.Pop(&pq).(*PacketItem)
		err := writer.WritePacket(item.ci, item.data)
		if err != nil {
			return fmt.Errorf("error writing packet: %v", err)
		}
		processedCount++
	}

	if verbose {
		fmt.Printf("Completed joining %d packets\n", processedCount)
	}

	return nil
}

// joinPcapFilesChunked joins pcap files using a chunked approach for lower memory usage
func joinPcapFilesChunked(inputFiles []string, writer *pcapgo.Writer, totalPackets int) error {
	// Create a shared channel for all input files
	packetChan := make(chan *PacketItem, BatchSize*2)

	// Use a wait group to track when all files have been processed
	var wg sync.WaitGroup
	wg.Add(len(inputFiles))

	// Start reading from each file in parallel
	for i, file := range inputFiles {
		go func(idx int, filename string) {
			var fileWg sync.WaitGroup
			fileWg.Add(1)

			fileChan := make(chan *PacketItem, BatchSize)

			// Process the file in its own goroutine
			go func() {
				err := processFileChunked(filename, idx, fileChan, &fileWg)
				if err != nil {
					fmt.Printf("Error processing file %s: %v\n", filename, err)
				}
			}()

			// Forward packets from this file to the main channel
			for packet := range fileChan {
				packetChan <- packet
			}

			wg.Done()
		}(i, file)
	}

	// Close the packet channel when all files are processed
	go func() {
		wg.Wait()
		close(packetChan)
	}()

	// Create a priority queue to order packets by timestamp
	pq := make(PriorityQueue, 0)
	heap.Init(&pq)

	// Process packets from the channel
	var processedCount int
	lastProgressUpdate := time.Now()

	// First, fill the priority queue with initial packets
	for packet := range packetChan {
		heap.Push(&pq, packet)

		// Once we have a good batch of packets, start processing
		if pq.Len() >= BatchSize {
			break
		}
	}

	// Now process the queue while continuing to read from the channel
	for {
		// Process packets from the queue while maintaining order
		for pq.Len() > 0 {
			// Write the earliest packet
			item := heap.Pop(&pq).(*PacketItem)
			err := writer.WritePacket(item.ci, item.data)
			if err != nil {
				return fmt.Errorf("error writing packet: %v", err)
			}

			processedCount++

			// Report progress periodically
			if verbose && (processedCount%ProgressInterval == 0 || time.Since(lastProgressUpdate) > 5*time.Second) {
				if totalPackets > 0 {
					fmt.Printf("Progress: %d/%d packets (%.1f%%)\n",
						processedCount, totalPackets, float64(processedCount)/float64(totalPackets)*100)
				} else {
					fmt.Printf("Progress: %d packets\n", processedCount)
				}
				lastProgressUpdate = time.Now()
			}
		}

		// Get more packets from the channel
		packet, more := <-packetChan
		if !more {
			// No more packets, we're done
			break
		}

		// Add to queue
		heap.Push(&pq, packet)
	}

	// Process any remaining packets in the queue
	for pq.Len() > 0 {
		item := heap.Pop(&pq).(*PacketItem)
		err := writer.WritePacket(item.ci, item.data)
		if err != nil {
			return fmt.Errorf("error writing packet: %v", err)
		}
		processedCount++
	}

	if verbose {
		fmt.Printf("Completed joining %d packets\n", processedCount)
	}

	return nil
}

func main() {
	// Parse command line arguments
	verboseFlag := flag.Bool("v", false, "Verbose mode: display detailed processing information")
	outputFile := flag.String("o", "", "Output PCAP file (default: joined.pcap)")
	numWorkersFlag := flag.String("workers", "0", "Number of worker goroutines (0 = use all CPU cores)")
	chunkedMode := flag.Bool("chunked", false, "Force chunked mode for low memory usage")
	directMode := flag.Bool("direct", false, "Force direct mode for faster processing")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] file1.pcap file2.pcap ... fileN.pcap\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported file formats: .pcap, .pcapng, .pcap.gz, .pcapng.gz, .gz\n")
	}

	flag.Parse()

	// Set global verbose flag
	verbose = *verboseFlag

	// Get input files from remaining arguments
	inputFiles := flag.Args()
	if len(inputFiles) == 0 {
		fmt.Println("Error: No input files specified")
		flag.Usage()
		os.Exit(1)
	}

	// Set output file
	var outputPath string
	if *outputFile != "" {
		outputPath = *outputFile
	} else {
		outputPath = "joined.pcap"
	}

	// Verify input files exist
	for _, file := range inputFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			fmt.Printf("Error: Input file %s does not exist\n", file)
			os.Exit(1)
		}
	}

	// Set the number of worker threads
	numWorkers := DefaultWorkers
	if *numWorkersFlag != "0" {
		var err error
		parsedWorkers, err := strconv.Atoi(*numWorkersFlag)
		if err != nil {
			fmt.Printf("Warning: Invalid worker count '%s', using default\n", *numWorkersFlag)
			numWorkers = runtime.GOMAXPROCS(0)
		} else {
			numWorkers = parsedWorkers
		}
	}
	if numWorkers <= 0 {
		numWorkers = runtime.GOMAXPROCS(0)
	}

	if verbose {
		fmt.Printf("Using %d worker threads\n", numWorkers)
		fmt.Printf("Input files: %d files\n", len(inputFiles))
		for i, file := range inputFiles {
			fmt.Printf("  [%d] %s\n", i+1, file)
		}
		fmt.Printf("Output file: %s\n", outputPath)
	}

	// Adjust runtime settings for optimal performance
	runtime.GOMAXPROCS(numWorkers)

	// Process the files
	startTime := time.Now()

	if verbose {
		fmt.Println("Starting join operation...")
	}

	err := joinPcapFiles(inputFiles, outputPath, *chunkedMode, *directMode)
	if err != nil {
		log.Fatalf("Error joining PCAP files: %v", err)
	}

	processingTime := time.Since(startTime)

	fmt.Printf("Successfully joined %d PCAP files into %s in %v\n",
		len(inputFiles), outputPath, processingTime)

	if verbose {
		fmt.Printf("\nPerformance statistics:\n")
		fmt.Printf("  Processing time: %.2f seconds\n", processingTime.Seconds())
	}
}
