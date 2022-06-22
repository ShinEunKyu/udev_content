package netlink

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type Mode int

// Mode determines event source: kernel events or udev-processed events.
// See libudev/libudev-monitor.c.
// 커널 이벤트와 udev 이벤트를 나타내는 Mode
const (
	// 커널 이벤트
	KernelEvent Mode = 1
	// Events that are processed by udev - much richer, with more attributes (such as vendor info, serial numbers and more).
	// Udev 이벤트 vendor 정보나 serial 정보 등의 Kernel 이벤트보다 더 많은 것을 제공.
	UdevEvent Mode = 2
)

// Generic connection
type NetlinkConn struct {
	Fd   int                     // 소켓 File Descriptor
	Addr syscall.SockaddrNetlink // Kernel과 User Space간의 통신 방식
}

type UEventConn struct {
	NetlinkConn

	// Options
	MatchedUEventLimit int // allow to stop monitor mode after X event(s) matched by the matcher(해당 값 만큼 매칭이 일치하면, 모니터 모드를 종료.)
}

// Connect allow to connect to system socket AF_NETLINK with family NETLINK_KOBJECT_UEVENT to
// catch events about block/char device
// see:
// - http://elixir.free-electrons.com/linux/v3.12/source/include/uapi/linux/netlink.h#L23
// - http://elixir.free-electrons.com/linux/v3.12/source/include/uapi/linux/socket.h#L11
func (c *UEventConn) Connect(mode Mode) (err error) {

	// AF_NETLINK : 커널 사용자 인터페이스 장치 / SOCK_RAW : 가공하지 않은 소켓 / NETLINK_KOBJECT_UEVENT : uevent를 Listen하기 위한 프로토콜
	if c.Fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_KOBJECT_UEVENT); err != nil {
		return
	}

	c.Addr = syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: uint32(mode), // mode : netlink.UdevEvent(Udev 이벤트)
	}

	if err = syscall.Bind(c.Fd, &c.Addr); err != nil {
		syscall.Close(c.Fd)
	}

	return
}

// Close allow to close file descriptor and socket bound
func (c *UEventConn) Close() error {
	return syscall.Close(c.Fd)
}

// 데이터를 수신하는 부분
func (c *UEventConn) msgPeek() (int, *[]byte, error) {
	var n int
	var err error
	buf := make([]byte, os.Getpagesize())
	for {
		// Just read how many bytes are available in the socket
		// Warning: syscall.MSG_PEEK is a blocking call
		// MSG_PEEK : 데이터가 읽혀지더라도 입력 버퍼에서 데이터가 지워지지 않음(입력버퍼에 수신된 데이터의 존재 유무 확인을 위한 옵션)
		if n, _, err = syscall.Recvfrom(c.Fd, buf, syscall.MSG_PEEK); err != nil {
			return n, &buf, err
		}

		// 모든 메시지를 버퍼 안에 저장할 수 있는 경우: break
		if n < len(buf) {
			break
		}

		// 충분하지 않은 경우 버퍼 크기를 늘림.
		buf = make([]byte, len(buf)+os.Getpagesize())
	}
	return n, &buf, err
}

func (c *UEventConn) msgRead(buf *[]byte) error {
	if buf == nil {
		return errors.New("empty buffer")
	}

	n, _, err := syscall.Recvfrom(c.Fd, *buf, 0)
	if err != nil {
		return err
	}

	// Extract only real data from buffer and return that
	*buf = (*buf)[:n]

	return nil
}

// ReadMsg allow to read an entire uevent msg
func (c *UEventConn) ReadMsg() (msg []byte, err error) {
	// Just read how many bytes are available in the socket
	_, buf, err := c.msgPeek()
	if err != nil {
		return nil, err
	}

	// Now read complete data
	err = c.msgRead(buf)

	return *buf, err
}

// ReadMsg allow to read an entire uevent msg
func (c *UEventConn) ReadUEvent() (*UEvent, error) {
	msg, err := c.ReadMsg()
	if err != nil {
		return nil, err
	}

	return ParseUEvent(msg)
}

// Monitor run in background a worker to read netlink msg in loop and notify
// when msg receive inside a queue using channel.
// To be notified with only relevant message, use Matcher.
// 모니터링을 진행하는 부분
func (c *UEventConn) Monitor(queue chan UEvent, errs chan error, matcher Matcher) chan struct{} {
	quit := make(chan struct{}, 1)

	// 정의한 Rule 파일이 있으면, 비교를 위해 Rule파일에있는 값을 정규표현식 Compile 함.
	if matcher != nil {
		if err := matcher.Compile(); err != nil {
			errs <- fmt.Errorf("Wrong matcher, err: %w", err)
			quit <- struct{}{}
			close(queue)
			return quit
		}
	}
	// Main
	go func() {
		bufToRead := make(chan *[]byte, 1) // 정보를 저장하기 위한 Byte Array 채널 생성
		count := 0                         // 매칭 Count를 위한 값
	loop:
		for {
			select {
			case <-quit:
				break loop // stop iteration in case of stop signal received
			case buf := <-bufToRead: // Read one by one(데이터를 수신 받았을 때,)
				err := c.msgRead(buf)
				if err != nil {
					errs <- fmt.Errorf("Unable to read uevent, err: %w", err)
					break loop // stop iteration in case of error
				}

				uevent, err := ParseUEvent(*buf) // 받은 데이터를 출력에 맞게 Parsing함.(중요)
				if err != nil {
					errs <- fmt.Errorf("Unable to parse uevent, err: %w", err)
					continue loop // Drop uevent if not known
				}

				// 정의한 Rule 파일이 있고,
				if matcher != nil {
					// 정의한 Rule과 일치하는지
					if !matcher.Evaluate(*uevent) {
						continue loop // Drop uevent if not match(다르면, 해당 Uevent를 Skip / 출력하지 않음)
					}
				}
				queue <- *uevent // 받은 Raw 데이터를 최종적으로 파싱한 출력 데이터를 queue에 전송
				count++
				// 매칭 임계값을 설정해 놓았고, 그 이상으로 탐지가 되었다면 종료.
				if c.MatchedUEventLimit > 0 && count >= c.MatchedUEventLimit {
					break loop // stop iteration when reach limit of uevent
				}
			default:
				_, buf, err := c.msgPeek() // 데이터를 수신하는 부분
				if err != nil {
					errs <- fmt.Errorf("Unable to check available uevent, err: %w", err)
					break loop // stop iteration in case of error
				}
				bufToRead <- buf // 데이터를 수신받아서, 파싱하기 위한 채널 데이터 전송. (case buf := <-bufToRead 로 이동.)
			}
		}
	}()
	return quit
}
