package netlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"
)

// See: http://elixir.free-electrons.com/linux/v3.12/source/lib/kobject_uevent.c#L45

const (
	ADD     KObjAction = "add"
	REMOVE  KObjAction = "remove"
	CHANGE  KObjAction = "change"
	MOVE    KObjAction = "move"
	ONLINE  KObjAction = "online"
	OFFLINE KObjAction = "offline"
	BIND    KObjAction = "bind"
	UNBIND  KObjAction = "unbind"
)

// The magic value used by udev, see https://github.com/systemd/systemd/blob/v239/src/libudev/libudev-monitor.c#L57
const libudevMagic = 0xfeedcafe

type KObjAction string

func (a KObjAction) String() string {
	return string(a)
}

// Action 값을 추출하는 함수
func ParseKObjAction(raw string) (a KObjAction, err error) {
	a = KObjAction(raw)
	switch a {
	case ADD, REMOVE, CHANGE, MOVE, ONLINE, OFFLINE, BIND, UNBIND:
	default:
		err = fmt.Errorf("unknow kobject action (got: %s)", raw)
	}
	return
}

type UEvent struct {
	Action KObjAction
	KObj   string
	Env    map[string]string
}

func (e UEvent) String() string {
	rv := fmt.Sprintf("%s@%s\000", e.Action.String(), e.KObj)
	for k, v := range e.Env {
		rv += k + "=" + v + "\000"
	}
	return rv
}

func (e UEvent) Bytes() []byte {
	return []byte(e.String())
}

func (e UEvent) Equal(e2 UEvent) (bool, error) {
	if e.Action != e2.Action {
		return false, fmt.Errorf("Wrong action (got: %s, wanted: %s)", e.Action, e2.Action)
	}

	if e.KObj != e2.KObj {
		return false, fmt.Errorf("Wrong kobject (got: %s, wanted: %s)", e.KObj, e2.KObj)
	}

	if len(e.Env) != len(e2.Env) {
		return false, fmt.Errorf("Wrong length of env (got: %d, wanted: %d)", len(e.Env), len(e2.Env))
	}

	var found bool
	for k, v := range e.Env {
		found = false
		for i, e := range e2.Env {
			if i == k && v == e {
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("Unable to find %s=%s env var from uevent", k, v)
		}
	}
	return true, nil
}

// Parse udev event created by udevd.
// The format of the data header is internal to udev and defined in libudev-monitor.c - see the udev_monitor_netlink_header struct.
// go-udev only looks at the "magic" number to filter out possibly invalid packets, and at the payload offset. Other fields of the header
// are ignored.
// Note, only some of the fields of the header use network byte order, for the rest udev uses native byte order of the platform.
// 데이터 헤더의 형식은 udev 내부 형식이고, libudev-monitor.c에 정의되어 있습니다.
func parseUdevEvent(raw []byte) (e *UEvent, err error) {
	// the magic number is stored in network byte order.
	// 앞의 8바이트를 제외하고, 이후의 4바이트(uint32)를 추출
	magic := binary.BigEndian.Uint32(raw[8:])
	// 추출한 4바이트의 값과 libudevMagic(0xfeedcafe)를 비교.
	if magic != libudevMagic {
		return nil, fmt.Errorf("cannot parse libudev event: magic number mismatch")
	}

	// the payload offset int is stored in native byte order.
	payloadoff := *(*uint32)(unsafe.Pointer(&raw[16]))
	if payloadoff >= uint32(len(raw)) {
		return nil, fmt.Errorf("cannot parse libudev event: invalid data offset")
	}
	// Action(맨 처음 옵션)이 시작되는 부분부터 0x00(끝나는 부분)으로 나눔.
	fields := bytes.Split(raw[payloadoff:], []byte{0x00}) // 0x00 = end of string
	if len(fields) == 0 {
		err = fmt.Errorf("cannot parse libudev event: data missing")
		return
	}

	envdata := make(map[string]string) // 파싱한 데이터를 넣을 변수

	// Key와 Value형태로 되어있는 Raw 데이터를 분리(=기준)하고, envdata에 Key / Value 형식으로 저장함.
	for _, envs := range fields[0 : len(fields)-1] {
		env := bytes.Split(envs, []byte("="))
		if len(env) != 2 {
			err = fmt.Errorf("cannot parse libudev event: invalid env data")
			return
		}
		envdata[string(env[0])] = string(env[1])
	}

	var action KObjAction
	action, err = ParseKObjAction(strings.ToLower(envdata["ACTION"])) // 파싱한 데이터 중 "Action" 값을 action변수에 저장
	if err != nil {
		return
	}

	// XXX: do we need kobj?(Env 변수에 "DEVPATH"라는게 어차피 들어가는데 따로 뺄 필요가 있을까..?(두번 출력) 라는 의미)
	kobj := envdata["DEVPATH"]

	e = &UEvent{
		Action: action,  // Action 값
		KObj:   kobj,    // Kernel Object(경로 값)
		Env:    envdata, // 나머지 정보 값들
	}

	return
}

// UEvent를 통해 받은 버퍼를 출력에 맞게 파싱.
func ParseUEvent(raw []byte) (e *UEvent, err error) {
	// 받은 데이터가 40Bytes가 넘고, 앞의 8Bytes가 "libudev\x00" 일때,(Test 시, 해당 조건에 들어갔음)
	if len(raw) > 40 && bytes.Equal(raw[:8], []byte("libudev\x00")) {
		return parseUdevEvent(raw)
	}
	fields := bytes.Split(raw, []byte{0x00}) // 0x00 = end of string

	if len(fields) == 0 {
		err = fmt.Errorf("Wrong uevent format")
		return
	}

	headers := bytes.Split(fields[0], []byte("@")) // 0x40 = @
	if len(headers) != 2 {
		err = fmt.Errorf("Wrong uevent header")
		return
	}

	action, err := ParseKObjAction(string(headers[0]))
	if err != nil {
		return
	}

	e = &UEvent{
		Action: action,
		KObj:   string(headers[1]),
		Env:    make(map[string]string),
	}

	for _, envs := range fields[1 : len(fields)-1] {
		env := bytes.Split(envs, []byte("="))
		if len(env) != 2 {
			err = fmt.Errorf("Wrong uevent env")
			return
		}
		e.Env[string(env[0])] = string(env[1])
	}
	return
}
