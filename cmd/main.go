package main

import (
	"errors"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-systemd/activation"
	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/exporters"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	configDir := kingpin.Flag("config.dir", "Config dir path.").Required().ExistingDir()
	configNames := kingpin.Flag("config.names", "Comma separated names of configs to load.").Required().String()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests (fd://0 for systemd activation).").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
	noLogTime := kingpin.Flag("log.no-timestamps", "Disable timestamps in log.").Bool()
	btfPath := kingpin.Flag("btf.path", "Optional BTF file path.").Default("").String()
	kingpin.Version(version.Print("cilium_ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	if *noLogTime {
		log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	}
	configs, err := config.ParseConfigs(*configDir, strings.Split(*configNames, ","))
	if err != nil {
		log.Fatalf("Error parsing configs: %v", err)
	}

	e, err := exporters.NewExporter(configs, *btfPath)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}
	http.HandleFunc("/maps", e.MapsHandler)
	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>eBPF Exporter</title></head>
			<body>
			<h1>Cilium eBPF Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			<p><a href="/maps">Maps</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatalf("Error sending response body: %s", err)
		}
	})

	err = listen(*listenAddress)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}

func listen(addr string) error {
	log.Printf("Listening on %s", addr)
	if strings.HasPrefix(addr, "fd://") {
		fd, err := strconv.Atoi(strings.TrimPrefix(addr, "fd://"))
		if err != nil {
			return fmt.Errorf("error extracting fd number from %q: %v", addr, err)
		}

		listeners, err := activation.Listeners()
		if err != nil {
			return fmt.Errorf("error getting activation listeners: %v", err)
		}

		if len(listeners) < fd+1 {
			return errors.New("no listeners passed via activation")
		}

		return http.Serve(listeners[fd], nil)
	}

	return http.ListenAndServe(addr, nil)
}
