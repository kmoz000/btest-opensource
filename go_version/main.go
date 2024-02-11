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
	"github.com/shirou/gopsutil/cpu"
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
	MESSAGE_PREFIX = 0x07
	MESSAGE_SIZE   = 12
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
			client.Write([]byte{2, 0, 0, 0})

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
			receivedUsername := strings.Trim(string(data[16:100]), "\x00")
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
			client.Write([]byte{1, 0, 0, 0})

			if action.Proto == "TCP" {
				go handleTCP(client, int(action.TxSize), action)
				// Send TCP socket port
				// Establish TCP socket
				// Send TCP data
			} else {
				// send ready message:
				// Send UDP data
				// bufPort := make([]byte, 2)
				store.CurrentPort++
				bufPort := []byte{byte(store.CurrentPort / UdpPortOffset)}
				// bufPort[5] = byte(store.CurrentPort / UdpPortOffset)
				// bufPort[6] = byte(store.CurrentPort % UdpPortOffset)

				_, err := client.Read(buffer)

				// fmt.Printf("buffer: %v\n", buffer[:12])
				if err == nil {
					client.Write(bufPort)
					localAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", store.CurrentPort))
					sock, err := net.ListenUDP("udp", localAddr)
					if err == nil {
						fmt.Printf("Server waiting for udp packets on port %d\n", store.CurrentPort)
						go handleUDP(sock, action, clientAddress, client)
						go handCPUload(client)
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
	message := []byte{MESSAGE_PREFIX}
	randomBytes := make([]byte, (size - 28 - 4 - 1))
	rand.Read(randomBytes)
	// const1, _ := hex.DecodeString("2cc82cc81bc0e12e6c3b6b405e0a0800450005dc")
	// const2, _ := hex.DecodeString("c0a803fdc0a80301080109")
	// const5, _ := hex.DecodeString("0a80301c0a803fd0")
	// const36, _ := hex.DecodeString("6c3b6c3b6b405e0a2cc81bc0e12e0800450005dc7fd4000040116cee")
	// const23, _ := hex.DecodeString("909080105c80000000004")
	// const28, _ := hex.DecodeString("780500d23171b00b26a21444e9721566ffffffffffff0e6673aa1086080045000148000000001011a9a600000000ffffffff00440043013449a001010600442c6340003d0000000000000000000000000000000000000e6673aa108600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501010c0e4d696b726f54696b2d6b6172696d370801790321062a8a2b3d07010e6673aa1086ff00000000000000000000000000000000000000000078501235507953801000738db690010f2041890889e00eb80b4a2479b52004bb1948010088110c32210c698a3c1c07211ac049091491d5d6078c3b0e060a2514c0950999600861202dc8ac9e32788131978a8525a08e890e4422340382b929104ce8144100c91a73ed0c290539e018072c91625721381c192ec80040daa3f0f6238862201000233312413094004326673c465c5608012d130c108a441f880362000c09019a411841288b1131208022b0a0e1e4c88817aa15a0405510b085c221809024339434c5903384c60800d400a85c482de992018230080c016c54d7403010a931642ca0a09880182eb064c90c2665b70930316f19c45524918794522031133199158c9595e7605d621164600047119f1e4b595a8d8c0e06391f42618609a432b06b9a5589576c8d36832f6142ab10848c85590e1260550452a48160754f061821850ac14c00202e003b101114b052f092ac3020500050008a03509209f6a88b0ac72089048198169000234984890219105420803d57870b1f301d54a05940c1da2811c6c8090bc990cd4871270fa08c14e0989b4148e86a500c52c93c4e8f8df4528be5226ea0c9e8b004451703c1b81196301f9b67310b62602a9915913821acbb78080ae82e65151b0a042c01832001098290adc000386b96e015e682515a51a8c0644451f0480048ac233df0913a362099b6c508f0126e5c7680c5a05a184112409f5343ec4230dd0049082320a1a118cc480f194444869091271ac5dc2a16b21115722344eff80a9e10067712f305a30580a8025385205922c230e92062f1bd2a4d08265a63c2d720bc00410088b1c2708850252aa0730551b402110c10b1043880500238c1194097c568094ad04405ab8421865030208ac84f458a25002402b5a480494fe01060096899c7353b2c518079185555269843cce0981cc89d0080645410b0028f6c0188f8678431a92c02fab6ff70008b898eae08838b285db0104c8bd8c5204d8eb00f3062a5825135609401e26ab3af1028004385a488889c118050e164808a828a9aba90058901a0c7201831d500554090411b62c8418a26ca00e6d8e04e07f1d084bfbe3168adc02235c27ea9ba466222908394e43cc311620112dd40602d8cc61c564888c8b9c9069848f08cc28922d62d4c33f8b4a844d0e3e930702467522102e0032201b393a2c6143487108192111c110b2f34db09780e8bb315284401609d7355f20070a7302253a2a09c73012c182e91252940e2d5d82cd424494e2b15a20a3905f96f960087484c44118d83cc1df83afb700a0b6f3080025c804500248061447ab011e30003c29890e0d10d331916e834a8ee7c254055a844daa00d22211344c522189542255e644824806492881cca4884a12e40a4062a002ba425bc213837ef8a1ad10a00504a245b430115618b380609ea288c385913904002bd409cc81de9b44b1c21de3ae001f6322790000d70c188290380c448ef16c411ad88bc886e904524ab49845a20093881c3821c80014041448c92508010881e82207bbcb17b3851232969c0ea")
	buf = append(buf, byte((tmp/256/256/256)%256), byte((tmp/256/256)%256), byte((tmp/256)%256), byte(tmp%256))
	buf = append(buf, message...)
	buf = append(buf, randomBytes...)
	// buf = append(buf, const28...)
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
func handCPUload(client net.Conn) {
	seqTCP := uint32(0)
	recbuf := make([]byte, 12)
	error_count := 0
	client.SetReadDeadline(<-time.After(2 * time.Second))
	for {
		percentages, _ := cpu.Percent(time.Second, false)
		fmt.Printf("Localcpu load:%f\n", percentages[0])
		seqbuff := [12]byte{7, byte(int(percentages[0] + 128)), byte((seqTCP / 256 / 256) % 256), byte((seqTCP / 256) % 256), byte(seqTCP % 256), 0, 0, 0, 0, 0, 0, 0}
		if _, err := client.Write(seqbuff[:]); err != nil {
			error_count++
		} else {
			if _, err := client.Read(recbuf); err == nil {
				fmt.Printf("Remote cpuload:%d\n", recbuf[1])
			}
		}
		seqTCP++
		if error_count > 10 {
			return
		}
		// time.Sleep(2 * time.Second)
	}
}
func handleUDP(sock *net.UDPConn, action Action, clientAddress net.Addr, client net.Conn) {
	// Implement the handleUDP function
	// Handle UDP logic
	// seqTCP := uint32(0)
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
			// fmt.Printf("%d ", seq)
			time.Sleep(250 * time.Millisecond)
			// if err_count > int(action.TxSize/10) || seq >= uint64(action.TxSize*action.TxSize) {
			if err_count > int(action.TxSize/10) {
				return
			}
		}
	case "RX":
	default:
		for {
			// received := make([]byte, action.TxSize)
			data := genPacket(seq, uint64(action.TxSize))
			clientAddress := netip.AddrPortFrom(netip.MustParseAddr(peerAd), uint16(sockPort+UdpPortOffset))
			if _, err := sock.WriteToUDPAddrPort(data, clientAddress); err != nil {
				err_count++
				fmt.Printf("Error from TX: %s\n", err.Error())
			}
			// fmt.Printf("%d ", seq)
			time.Sleep(250 * time.Millisecond)
			seq++
			// if err_count > int(action.TxSize/10) || seq >= uint64(action.TxSize*action.TxSize) {
			// if size, address, err := sock.ReadFromUDP(received); size > 0 && err == nil {
			// 	fmt.Printf("received seq: %d from (%s)", binary.LittleEndian.Uint32(received[0:4]), address.String())
			// } else {
			// 	err_count++
			// }
			if err_count > int(10) {
				return
			}
		}
	}
}
