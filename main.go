package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pilebones/go-udev/crawler"
	"github.com/pilebones/go-udev/netlink"

	"github.com/kr/pretty"
)

var (
	filePath              *string
	monitorMode, infoMode *bool
)

func init() {
	filePath = flag.String("file", "", "Optionnal input file path with matcher-rules (default: no matcher)")
	monitorMode = flag.Bool("monitor", false, "Enable monitor mode")
	infoMode = flag.Bool("info", false, "Enable crawler mode")
}

func main() {
	flag.Parse()

	*monitorMode = true // Debuging을 위한 Option추가(모니터 모드 강제 활성화)
	// *filePath = "matcher.sample" // Debuging을 위한 Option추가(Rule 파일 설정)

	matcher, err := getOptionnalMatcher() // 원하는 Device만 출력하는 Rule을 적용할 때 사용.(Rule은 "matcher.sample" 참고)
	if err != nil {
		log.Fatalln(err)
	}

	if monitorMode == nil && infoMode == nil {
		log.Fatalln("You should use only one mode:", os.Args[0], "-monitor|-info")
	}

	if (monitorMode != nil && *monitorMode) && (infoMode != nil && *infoMode) {
		log.Fatalln("Unable to enable both mode : monitor & info")
	}

	if *monitorMode {
		monitor(matcher)
	}

	if *infoMode {
		info(matcher)
	}
}

// info run info mode
func info(matcher netlink.Matcher) {
	log.Println("Get existing devices...")

	queue := make(chan crawler.Device)
	errors := make(chan error)
	quit := crawler.ExistingDevices(queue, errors, matcher)

	// Signal handler to quit properly monitor mode
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-signals
		log.Println("Exiting info mode...")
		close(quit)
		os.Exit(0)
	}()

	// Handling message from queue
	for {
		select {
		case device, more := <-queue:
			if !more {
				log.Println("Finished processing existing devices")
				return
			}
			log.Println("Detect device at", device.KObj, "with env", device.Env)
		case err := <-errors:
			log.Println("ERROR:", err)
		}
	}
}

// monitor run monitor mode(모니터 모드 함수)
func monitor(matcher netlink.Matcher) {
	log.Println("Monitoring UEvent kernel message to user-space...")

	conn := new(netlink.UEventConn)
	// 소켓 통신(netlink.UdevEvent : 커널 이벤트가 아닌 udev 이벤트로 설정 / 커널 이벤트보다 더 많은 정보를 제공)
	if err := conn.Connect(netlink.UdevEvent); err != nil {
		log.Fatalln("Unable to connect to Netlink Kobject UEvent socket")
	}
	defer conn.Close()

	queue := make(chan netlink.UEvent)           // 장치 Event가 발생했을 때 해당 정보를 담기 위한 Queue
	errors := make(chan error)                   // Error 관련 채널
	quit := conn.Monitor(queue, errors, matcher) // 모니터 모드 시작(quit : 종료)

	// Signal handler to quit properly monitor mode
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-signals
		log.Println("Exiting monitor mode...")
		close(quit)
		os.Exit(0)
	}()

	// Handling message from queue
	// 메시지를 출력하는 부분
	for {
		select {
		case uevent := <-queue:
			log.Println("Handle", pretty.Sprint(uevent))
		case err := <-errors:
			log.Println("ERROR:", err)
		}
	}

}

// getOptionnalMatcher Parse and load config file which contains rules for matching
// 규칙을 정해놓은 파일이 존재하는지 확인하고, 로드함.
func getOptionnalMatcher() (matcher netlink.Matcher, err error) {
	if filePath == nil || *filePath == "" {
		return nil, nil
	}

	stream, err := ioutil.ReadFile(*filePath)
	if err != nil {
		return nil, err
	}

	if stream == nil {
		return nil, fmt.Errorf("Empty, no rules provided in \"%s\", err: %w", *filePath, err)
	}

	var rules netlink.RuleDefinitions
	if err := json.Unmarshal(stream, &rules); err != nil {
		return nil, fmt.Errorf("Wrong rule syntax, err: %w", err)
	}

	return &rules, nil
}
