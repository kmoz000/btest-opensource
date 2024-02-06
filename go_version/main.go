package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Store struct to hold constants
type Store struct {
	CurrentPort int
}

// Action struct to represent an action
// Action struct to represent an action
type Action struct {
	Proto         string
	Direction     string
	Random        bool
	TCPConnCount  int
	TxSize        uint16
	Unknown       uint32
	RemoteTxSpeed uint32
	LocalTxSpeed  uint32
}

// Constants for the application
const (
	BTestPort      = 2000
	UdpPortOffset  = 256
	DefaultBufSize = 1024
)

var store = Store{
	CurrentPort: BTestPort,
}

func main() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	username := "btest"
	if user := os.Getenv("USERNAME"); user != "" {
		username = user
	}
	password := "btest"
	if pass := os.Getenv("PASSWORD"); pass != "" {
		password = pass
	}
	requireAuth := true
	if isAuth := os.Getenv("AUTH"); isAuth != "" {
		requireAuth, _ = strconv.ParseBool(isAuth)
	}

	authIsValid := false
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", BTestPort))
	if err != nil {
		fmt.Printf("Failed to bind socket: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("Server waiting for client connection on port %d\n", BTestPort)

	for {
		client, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to establish a connection: %v\n", err)
			continue
		}

		clientAddress := client.RemoteAddr()
		fmt.Printf("Connection from %s\n", clientAddress.String())

		// Sending hello
		client.Write([]byte{1, 0, 0, 0})

		// Reading reply
		buffer := make([]byte, DefaultBufSize)
		client.Read(buffer)
		action := unpackCmd(buffer)
		fmt.Printf("%+v\n", action)

		// Send auth requested command
		if requireAuth {
			// Sending Data
			client.Write(hexDecode("02000000"))

			// Setting Digest
			randomDigest := generateRandomArray()
			// Sending empty_array Digest
			client.Write(randomDigest[:])

			// Receiving Data
			data := make([]byte, DefaultBufSize)
			client.Read(data)

			// Printing Data
			currentPassHash := hashGen(password, randomDigest)
			receivedPassHash := hex.EncodeToString(data[:16])
			receivedUsername := strings.TrimRight(string(data[16:100]), "\x00")
			currentUsername := username
			isValid := receivedUsername == currentUsername && receivedPassHash == currentPassHash
			authIsValid = isValid

			fmt.Printf("- client auth data is : username %s, password digest: %s\n", receivedUsername, receivedPassHash)
			fmt.Printf("- server auth data is : username %s, password digest: %s\n", currentUsername, currentPassHash)
			fmt.Printf("is credentials valid: %t\n", isValid)

			// Sending Authentication Acceptance
			if isValid {
				client.Write(hexDecode("01000000"))
			} else {
				client.Write(hexDecode("00000000"))
			}
		}

		if !requireAuth || authIsValid {
			fmt.Println("Sending hello")
			// Sending hello
			client.Write(hexDecode("01000000"))

			if action.Proto == "TCP" {
				go handleTCP(client, int(action.TxSize), action)
				// Send TCP socket port
				// Establish TCP socket
				// Send TCP data
			} else {
				// send ready message:
				// Send UDP data
				bufPort := make([]byte, 2)
				store.CurrentPort++
				bufPort[0] = byte(store.CurrentPort / UdpPortOffset)
				bufPort[1] = byte(store.CurrentPort % UdpPortOffset)

				_, err := client.Read(buffer)
				if err == nil {
					client.Write(bufPort)
					localAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", store.CurrentPort))
					sock, err := net.ListenUDP("udp", localAddr)
					if err == nil {
						fmt.Printf("Server waiting for udp packets on port %d\n", store.CurrentPort)
						go handleUDP(sock, action, clientAddress)
					}
				} else {
					client.Write(hexDecode("00000000"))
				}
			}
		}
	}
}

func unpackCmd(data []byte) Action {
	cmdList := make([]byte, len(data))
	copy(cmdList, data)

	cmd := Action{
		Proto:         "UDP",
		Direction:     "TXRX",
		Random:        cmdList[2] == 0,
		TCPConnCount:  1,
		TxSize:        binary.LittleEndian.Uint16(cmdList[4:6]),
		Unknown:       binary.LittleEndian.Uint32(cmdList[6:10]),
		RemoteTxSpeed: binary.LittleEndian.Uint32(cmdList[10:14]),
		LocalTxSpeed:  binary.LittleEndian.Uint32(cmdList[14:18]),
	}

	if cmdList[0] != 0 {
		cmd.Proto = "TCP"
	}

	switch cmdList[1] {
	case 1:
		cmd.Direction = "RX"
	case 2:
		cmd.Direction = "TX"
	}

	return cmd
}

func hexDecode(hexString string) []byte {
	decoded, _ := hex.DecodeString(hexString)
	return decoded
}

func generateRandomArray() [16]byte {
	var randomArray [16]byte
	_, err := rand.Read(randomArray[:])
	if err != nil {
		panic(fmt.Errorf("failed to generate random array: %v", err))
	}
	return randomArray
}

func hashGen(inputPassword string, nonce [16]byte) string {
	// Create an MD5 hasher
	var hash [16]byte
	md5Hash := md5.New()

	// Compute MD5 hash with input_password and nonce
	md5Hash.Write([]byte(inputPassword))
	md5Hash.Write(nonce[:])
	hash = [16]byte(md5Hash.Sum(nil))

	// Reset the MD5 hasher
	md5Hash.Reset()

	// Compute MD5 hash with input_password and previous hash
	md5Hash.Write([]byte(inputPassword))
	md5Hash.Write(hash[:])
	hash = [16]byte(md5Hash.Sum(nil))

	// Obtain the hexadecimal representation of the computed MD5 hash
	computedMD5Hex := hex.EncodeToString(hash[:])
	return computedMD5Hex
}

// func generatePrefixedBytes(seq uint64, length int) []byte {
// 	// Create a slice with the specified length and prefix
// 	// Extend the slice with the provided prefix
// 	var buf []byte
// 	tmp := seq // Replace with the actual value from your code
// 	buf = append(buf, byte((tmp/256/256/256)%256), byte((tmp/256/256)%256), byte((tmp/256)%256), byte(tmp%256))
// 	// buf = append(buf, byte(0), byte(0), byte(0), byte(0)) // Uncomment this line to use random values instead of zeros

// 	// Efficiently fill the remaining portion of the slice with zeros
// 	buf = append(buf, bytes.Repeat([]byte{0}, length-4)...)

//		return buf
//	}
func genPacket(seq uint64, size uint64) []byte {
	var buf []byte
	tmp := seq // Replace with the actual value from your code
	// empty16 := make([]byte, 16)
	randomBytes := make([]byte, (size - 28 - 4))
	rand.Read(randomBytes)
	// const1, _ := hex.DecodeString("2cc82cc81bc0e12e6c3b6b405e0a0800450005dc")
	// const2, _ := hex.DecodeString("c0a803fdc0a80301080109")
	// const5, _ := hex.DecodeString("0a80301c0a803fd0")
	// const36, _ := hex.DecodeString("6c3b6c3b6b405e0a2cc81bc0e12e0800450005dc7fd4000040116cee")
	// const23, _ := hex.DecodeString("909080105c80000000004")
	// const28, _ := hex.DecodeString("016c3b6b405e0a2cc81bc0e12e0800456c3b6c3b6b405e0a2cc81bc0e12e0800450005dc")
	buf = append(buf, byte((tmp/256/256/256)%256), byte((tmp/256/256)%256), byte((tmp/256)%256), byte(tmp%256))
	buf = append(buf, randomBytes...)
	return buf
}
func getIPAndPort(addr net.Addr) (string, int) {
	switch v := addr.(type) {
	case *net.TCPAddr:
		return v.IP.String(), v.Port
	case *net.UDPAddr:
		return v.IP.String(), v.Port
	default:
		// If it's a custom type that implements net.Addr, you can handle it here
		// For simplicity, assuming the format is "IP:Port"
		parts := strings.Split(v.String(), ":")
		if len(parts) == 2 {
			port, _ := strconv.Atoi(parts[1])
			return parts[0], port
		}
		return "", 0
	}
}

func handleTCP(client net.Conn, txSize int, action Action) {
	// Implement the handleTCP function
	// Handle TCP logic
}

func handleUDP(sock *net.UDPConn, action Action, clientAddress net.Addr) {
	// Implement the handleUDP function
	// Handle UDP logic
	seq := uint64(0)
	peerAd, _ := getIPAndPort(clientAddress)
	err_count := 0
	_, sockPort := getIPAndPort(sock.LocalAddr())
	switch action.Direction {
	case "TX":
		for {
			data := genPacket(seq, uint64(action.TxSize))
			if _, err := sock.WriteToUDPAddrPort(data, netip.AddrPortFrom(netip.MustParseAddr(peerAd), uint16(sockPort+UdpPortOffset))); err != nil {
				err_count++
				fmt.Printf("Error from TX: %s\n", err.Error())
			}
			seq++
			fmt.Printf("%d ", seq)
			time.Sleep(250 * time.Millisecond)
			if err_count > int(action.TxSize/10) || seq >= uint64(action.TxSize*action.TxSize) {
				return
			}
		}
	case "RX":
	default:

	}
}
