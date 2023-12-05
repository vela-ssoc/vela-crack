package mysql

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

var pubKey = []byte("-----BEGIN PUBLIC KEY-----\n" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAol0Z8G8U+25Btxk/g/fm\n" +
	"UAW/wEKjQCTjkibDE4B+qkuWeiumg6miIRhtilU6m9BFmLQSy1ltYQuu4k17A4tQ\n" +
	"rIPpOQYZges/qsDFkZh3wyK5jL5WEFVdOasf6wsfszExnPmcZS4axxoYJfiuilrN\n" +
	"hnwinBAqfi3S0sw5MpSI4Zl1AbOrHG4zDI62Gti2PKiMGyYDZTS9xPrBLbN95Kby\n" +
	"FFclQLEzA9RJcS1nHFsWtRgHjGPhhjCQxEm9NQ1nePFhCfBfApyfH1VM2VCOQum6\n" +
	"Ci9bMuHWjTjckC84mzF99kOxOWVU7mwS6gnJqBzpuz8t3zq8/iQ2y7QrmZV+jTJP\n" +
	"WQIDAQAB\n" +
	"-----END PUBLIC KEY-----\n")

type Mysql struct {
	Password   string
	Username   string
	Addr       string
	Network    string
	netConn    net.Conn
	buff       buffer
	flags      clientFlag
	TLS        *tls.Config
	pubKey     []byte
	DBName     string
	Attributes string
	sequence   uint8
}

func (my *Mysql) Close() error {
	if my.netConn != nil {
		my.netConn.Close()
	}
	my.netConn = nil
	return nil
}

func (my *Mysql) Dail() error {
	var err error
	// 连接到MySQL服务器
	my.netConn, err = net.Dial(my.Network, my.Addr) // 替换成你的MySQL服务器IP和端口
	if err != nil {
		return err
	}

	my.buff = newBuffer(my.netConn)
	return nil
}

// Client Authentication Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
func (my *Mysql) WriteHandshakeResponsePacket(authResp []byte, plugin string) error {
	// Adjust client flags based on server support
	clientFlags := clientProtocol41 |
		clientSecureConn |
		clientLongPassword |
		clientTransactions |
		clientLocalFiles |
		clientPluginAuth |
		clientMultiResults |
		clientConnectAttrs |
		my.flags&clientLongFlag

	// encode length of the auth plugin data
	var authRespLEIBuf [9]byte
	authRespLen := len(authResp)
	authRespLEI := appendLengthEncodedInteger(authRespLEIBuf[:0], uint64(authRespLen))
	if len(authRespLEI) > 1 {
		// if the length can not be written in 1 byte, it must be written as a
		// length encoded integer
		clientFlags |= clientPluginAuthLenEncClientData
	}

	pktLen := 4 + 4 + 1 + 23 + len(my.Username) + 1 + len(authRespLEI) + len(authResp) + 21 + 1

	// To specify a db name
	if n := len(my.DBName); n > 0 {
		clientFlags |= clientConnectWithDB
		pktLen += n + 1
	}

	// 1 byte to store length of all key-values
	// NOTE: Actually, this is length encoded integer.
	// But we support only len(connAttrBuf) < 251 for now because takeSmallBuffer
	// doesn't support buffer size more than 4096 bytes.
	// TODO(methane): Rewrite buffer management.
	pktLen += 1 + len(my.Attributes)

	// Calculate packet length and get buffer with that size
	data, err := my.buff.takeSmallBuffer(pktLen + 4)
	if err != nil {
		// cannot take the buffer. Something must be wrong with the connection
		return errBadConnNoWrite
	}

	// ClientFlags [32 bit]
	data[4] = byte(clientFlags)
	data[5] = byte(clientFlags >> 8)
	data[6] = byte(clientFlags >> 16)
	data[7] = byte(clientFlags >> 24)

	// MaxPacketSize [32 bit] (none)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Collation ID [1 byte]
	cname := defaultCollation

	var found bool
	data[12], found = collations[cname]
	if !found {
		// Note possibility for false negatives:
		// could be triggered  although the collation is valid if the
		// collations map does not contain entries the server supports.
		return fmt.Errorf("unknown collation: %q", cname)
	}

	// Filler [23 bytes] (all 0x00)
	pos := 13
	for ; pos < 13+23; pos++ {
		data[pos] = 0
	}

	// SSL Connection Request Packet
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	if my.TLS != nil {
		// Send TLS / SSL request packet
		if err := my.WritePacket(data[:(4+4+1+23)+4]); err != nil {
			return err
		}

		// Switch to TLS
		tlsConn := tls.Client(my.netConn, my.TLS)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		my.netConn = tlsConn
		my.buff.nc = tlsConn
	}

	// User [null terminated string]
	if len(my.Username) > 0 {
		pos += copy(data[pos:], my.Username)
	}
	data[pos] = 0x00
	pos++

	// Auth Data [length encoded integer]
	pos += copy(data[pos:], authRespLEI)
	pos += copy(data[pos:], authResp)

	// Databasename [null terminated string]
	if len(my.DBName) > 0 {
		pos += copy(data[pos:], my.DBName)
		data[pos] = 0x00
		pos++
	}

	pos += copy(data[pos:], plugin)
	data[pos] = 0x00
	pos++

	// Connection Attributes
	data[pos] = byte(len(my.Attributes))
	pos++
	pos += copy(data[pos:], []byte(my.Attributes))

	// Send Auth packet
	return my.WritePacket(data[:pos])
}

/******************************************************************************
*                              Result Packets                                 *
******************************************************************************/

func (my *Mysql) ReadAuthResult() ([]byte, string, error) {
	data, err := my.readPacket()
	if err != nil {
		return nil, "", err
	}

	// packet indicator
	switch data[0] {

	case iOK:
		// resultUnchanged, since auth happens before any queries or
		// commands have been executed.
		return nil, "", nil

	case iAuthMoreData:
		return data[1:], "", err

	case iEOF:
		if len(data) == 1 {
			// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::OldAuthSwitchRequest
			return nil, "mysql_old_password", nil
		}
		pluginEndIndex := bytes.IndexByte(data, 0x00)
		if pluginEndIndex < 0 {
			return nil, "", ErrMalformPkt
		}
		plugin := string(data[1:pluginEndIndex])
		authData := data[pluginEndIndex+1:]
		return authData, plugin, nil

	default: // Error otherwise
		return nil, "", my.handleErrorPacket(data)
	}
}

// Returns error if Packet is not a 'Result OK'-Packet
func (my *Mysql) readResultOK() error {
	data, err := my.readPacket()
	if err != nil {
		return err
	}

	if data[0] == iOK {
		return my.OkPacket(data)
	}

	return my.handleErrorPacket(data)
}

// Ok Packet
// http://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-OK_Packet
func (my *Mysql) OkPacket(data []byte) error {
	var n, m int
	var affectedRows, insertId uint64

	// 0x00 [1 byte]

	// Affected rows [Length Coded Binary]
	affectedRows, _, n = readLengthEncodedInteger(data[1:])

	// Insert id [Length Coded Binary]
	insertId, _, m = readLengthEncodedInteger(data[1+n:])

	NoEffect(affectedRows)
	NoEffect(insertId)
	NoEffect(n)
	NoEffect(m)

	// Update for the current statement result (only used by
	// readResultSetHeaderPacket).
	//if len(mc.result.affectedRows) > 0 {
	//	mc.result.affectedRows[len(mc.result.affectedRows)-1] = int64(affectedRows)
	//}
	//if len(mc.result.insertIds) > 0 {
	//	mc.result.insertIds[len(mc.result.insertIds)-1] = int64(insertId)
	//}

	// server_status [2 bytes]
	//mc.status = readStatus(data[1+n+m : 1+n+m+2])
	//if mc.status&statusMoreResultsExists != 0 {
	//	return nil
	//}

	// warning count [2 bytes]

	return nil
}

// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchResponse
func (my *Mysql) WriteAuthSwitchPacket(authData []byte) error {
	pktLen := 4 + len(authData)
	data, err := my.buff.takeSmallBuffer(pktLen)
	if err != nil {
		// cannot take the buffer. Something must be wrong with the connection
		return errBadConnNoWrite
	}

	// Add the auth data [EOF]
	copy(data[4:], authData)
	return my.WritePacket(data)
}

func (my *Mysql) HandleAuthResult(oldAuthData []byte, plugin string) error {
	// Read Result Packet
	authData, newPlugin, err := my.ReadAuthResult()
	if err != nil {
		return err
	}

	// handle auth plugin switch, if requested
	if newPlugin != "" {
		// If CLIENT_PLUGIN_AUTH capability is not supported, no new cipher is
		// sent and we have to keep using the cipher sent in the init packet.
		if authData == nil {
			authData = oldAuthData
		} else {
			// copy data from read buffer to owned slice
			copy(oldAuthData, authData)
		}

		plugin = newPlugin

		authResp, err := my.auth(authData, plugin)
		if err != nil {
			return err
		}
		if err = my.WriteAuthSwitchPacket(authResp); err != nil {
			return err
		}

		// Read Result Packet
		authData, newPlugin, err = my.ReadAuthResult()
		if err != nil {
			return err
		}

		// Do not allow to change the auth plugin more than once
		if newPlugin != "" {
			return ErrMalformPkt
		}
	}

	switch plugin {

	// https://dev.mysql.com/blog-archive/preparing-your-community-connector-for-mysql-8-part-2-sha256/
	case "caching_sha2_password":
		switch len(authData) {
		case 0:
			return nil // auth successful
		case 1:
			switch authData[0] {
			case cachingSha2PasswordFastAuthSuccess:
				return nil

			case cachingSha2PasswordPerformFullAuthentication:
				if my.TLS != nil || my.Network == "unix" {
					// write cleartext auth packet
					err = my.WriteAuthSwitchPacket(append([]byte(my.Password), 0))
					if err != nil {
						return err
					}
				} else {
					// request public key from server
					data, err := my.buff.takeSmallBuffer(4 + 1)
					if err != nil {
						return err
					}
					data[4] = cachingSha2PasswordRequestPublicKey
					err = my.WritePacket(data)
					if err != nil {
						return err
					}

					if data, err = my.readPacket(); err != nil {
						return err
					}

					if data[0] != iAuthMoreData {
						return fmt.Errorf("unexpected resp from server for caching_sha2_password, perform full authentication")
					}

					// parse public key
					block, rest := pem.Decode(data[1:])
					if block == nil {
						return fmt.Errorf("no pem data found, data: %s", rest)
					}
					pkix, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return err
					}
					pub := pkix.(*rsa.PublicKey)

					// send encrypted password
					err = my.SendEncryptedPassword(oldAuthData, pub)
					if err != nil {
						return err
					}
				}
				return my.readResultOK()

			default:
				return ErrMalformPkt
			}
		default:
			return ErrMalformPkt
		}

	case "sha256_password":
		switch len(authData) {
		case 0:
			return nil // auth successful
		default:
			block, _ := pem.Decode(authData)
			if block == nil {
				return fmt.Errorf("no Pem data found, data: %s", authData)
			}

			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			}

			// send encrypted password
			err = my.SendEncryptedPassword(oldAuthData, pub.(*rsa.PublicKey))
			if err != nil {
				return err
			}
			return my.readResultOK()
		}

	default:
		return nil // auth successful
	}

	return err
}

func (my *Mysql) auth(authData []byte, plugin string) ([]byte, error) {
	switch plugin {
	case "caching_sha2_password":
		authResp := scrambleSHA256Password(authData, my.Password)
		return authResp, nil

	case "mysql_old_password":
		if len(my.Password) == 0 {
			return nil, nil
		}
		// Note: there are edge cases where this should work but doesn't;
		// this is currently "wontfix":
		// https://github.com/go-sql-driver/mysql/issues/184
		authResp := append(scrambleOldPassword(authData[:8], my.Password), 0)
		return authResp, nil

	case "mysql_clear_password":
		// http://dev.mysql.com/doc/refman/5.7/en/cleartext-authentication-plugin.html
		// http://dev.mysql.com/doc/refman/5.7/en/pam-authentication-plugin.html
		return append([]byte(my.Password), 0), nil

	case "mysql_native_password":
		// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
		// Native password authentication only need and will need 20-byte challenge.
		authResp := scramblePassword(authData[:20], my.Password)
		return authResp, nil

	case "sha256_password":
		if len(my.Password) == 0 {
			return []byte{0}, nil
		}
		// unlike caching_sha2_password, sha256_password does not accept
		// cleartext password on unix transport.
		if my.TLS != nil {
			// write cleartext auth packet
			return append([]byte(my.Password), 0), nil
		}

		block, _ := pem.Decode(pubKey)
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		enc, err := my.EncryptPassword(my.Password, authData, pub.(*rsa.PublicKey))
		return enc, err

	default:
		return nil, ErrUnknownPlugin
	}
}

func (my *Mysql) EncryptPassword(password string, seed []byte, pub *rsa.PublicKey) ([]byte, error) {
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(seed)
		plain[i] ^= seed[j]
	}
	sha1 := sha1.New()
	return rsa.EncryptOAEP(sha1, rand.Reader, pub, plain, nil)
}

func (my *Mysql) SendEncryptedPassword(seed []byte, pub *rsa.PublicKey) error {
	enc, err := encryptPassword(my.Password, seed, pub)
	if err != nil {
		return err
	}
	return my.WriteAuthSwitchPacket(enc)
}

// Write packet buffer 'data'
func (my *Mysql) WritePacket(data []byte) error {
	pktLen := len(data) - 4
	for {
		var size int
		if pktLen >= maxPacketSize {
			data[0] = 0xff
			data[1] = 0xff
			data[2] = 0xff
			size = maxPacketSize
		} else {
			data[0] = byte(pktLen)
			data[1] = byte(pktLen >> 8)
			data[2] = byte(pktLen >> 16)
			size = pktLen
		}

		data[3] = my.sequence

		// Write packet
		if err := my.netConn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			return err
		}

		n, err := my.netConn.Write(data[:4+size])
		if err == nil && n == 4+size {
			my.sequence++
			if size != maxPacketSize {
				return nil
			}
			pktLen -= size
			data = data[size:]
			continue
		}

		if err != nil {
			if n == 0 && pktLen == len(data)-4 {
				// only for the first loop iteration when nothing was written yet
				return errBadConnNoWrite
			}
		}
		return ErrInvalidConn
	}
}

func (my *Mysql) handleErrorPacket(data []byte) error {
	if data[0] != iERR {
		return ErrMalformPkt
	}

	// 0xff [1 byte]

	// Error Number [16 bit uint]
	errno := binary.LittleEndian.Uint16(data[1:3])

	// 1792: ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
	// 1290: ER_OPTION_PREVENTS_STATEMENT (returned by Aurora during failover)
	if errno == 1792 || errno == 1290 {
		// Oops; we are connected to a read-only connection, and won't be able
		// to issue any write statements. Since RejectReadOnly is configured,
		// we throw away this connection hoping this one would have write
		// permission. This is specifically for a possible race condition
		// during failover (e.g. on AWS Aurora). See README.md for more.
		//
		// We explicitly close the connection before returning
		// driver.ErrBadConn to ensure that `database/sql` purges this
		// connection and initiates a new one for next statement next time.
		return driver.ErrBadConn
	}

	me := &MySQLError{Number: errno}

	pos := 3

	// SQL State [optional: # + 5bytes string]
	if data[3] == 0x23 {
		copy(me.SQLState[:], data[4:4+5])
		pos = 9
	}

	// Error Message [string]
	me.Message = string(data[pos:])

	return me
}

// Handshake Initialization Packet
// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
func (my *Mysql) readHandshakePacket() (data []byte, plugin string, err error) {
	data, err = my.readPacket()
	if err != nil {
		// for init we can rewrite this to ErrBadConn for sql.Driver to retry, since
		// in connection initialization we don't risk retrying non-idempotent actions.
		if err == ErrInvalidConn {
			return nil, "", driver.ErrBadConn
		}
		return
	}

	if data[0] == iERR {
		return nil, "", my.handleErrorPacket(data)
	}

	// protocol version [1 byte]
	if data[0] < minProtocolVersion {
		return nil, "", fmt.Errorf(
			"unsupported protocol version %d. Version %d or higher is required",
			data[0],
			minProtocolVersion,
		)
	}

	// server version [null terminated string]
	// connection id [4 bytes]
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	// first part of the password cipher [8 bytes]
	authData := data[pos : pos+8]

	// (filler) always 0x00 [1 byte]
	pos += 8 + 1

	// capability flags (lower 2 bytes) [2 bytes]
	my.flags = clientFlag(binary.LittleEndian.Uint16(data[pos : pos+2]))
	if my.flags&clientProtocol41 == 0 {
		return nil, "", ErrOldProtocol
	}
	pos += 2

	if len(data) > pos {
		// character set [1 byte]
		// status flags [2 bytes]
		// capability flags (upper 2 bytes) [2 bytes]
		// length of auth-plugin-data [1 byte]
		// reserved (all [00]) [10 bytes]
		pos += 1 + 2 + 2 + 1 + 10

		// second part of the password cipher [minimum 13 bytes],
		// where len=MAX(13, length of auth-plugin-data - 8)
		//
		// The web documentation is ambiguous about the length. However,
		// according to mysql-5.7/sql/auth/sql_authentication.cc line 538,
		// the 13th byte is "\0 byte, terminating the second part of
		// a scramble". So the second part of the password cipher is
		// a NULL terminated string that's at least 13 bytes with the
		// last byte being NULL.
		//
		// The official Python library uses the fixed length 12
		// which seems to work but technically could have a hidden bug.
		authData = append(authData, data[pos:pos+12]...)
		pos += 13

		// EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
		// \NUL otherwise
		if end := bytes.IndexByte(data[pos:], 0x00); end != -1 {
			plugin = string(data[pos : pos+end])
		} else {
			plugin = string(data[pos:])
		}

		// make a memory safe copy of the cipher slice
		var b [20]byte
		copy(b[:], authData)
		return b[:], plugin, nil
	}

	// make a memory safe copy of the cipher slice
	var b [8]byte
	copy(b[:], authData)
	return b[:], plugin, nil
}

func (my *Mysql) readPacket() ([]byte, error) {
	var prevData []byte
	for {
		// read packet header
		data, err := my.buff.readNext(4)
		if err != nil {
			return nil, ErrInvalidConn
		}

		// packet length [24 bit]
		pktLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)

		// packets with length 0 terminate a previous packet which is a
		// multiple of (2^24)-1 bytes long
		if pktLen == 0 {
			// there was no previous packet
			if prevData == nil {
				return nil, ErrInvalidConn
			}
			return prevData, nil
		}

		if data[3] != my.sequence {
			return nil, ErrPktSync
		}
		my.sequence++

		// read packet body [pktLen bytes]
		data, err = my.buff.readNext(pktLen)
		if err != nil {
			return nil, ErrInvalidConn
		}

		// return data if this was the last packet
		if pktLen < maxPacketSize {
			// zero allocations for non-split packets
			if prevData == nil {
				return data, nil
			}

			return append(prevData, data...), nil
		}
		prevData = append(prevData, data...)
	}
}
