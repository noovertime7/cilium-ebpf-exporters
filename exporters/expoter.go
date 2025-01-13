package exporters

import (
	"github.com/aquasecurity/libbpfgo"
	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Namespace to use for all metrics
const prometheusNamespace = "cilium_ebpf_exporter"

// Exporter is a ebpf_exporter instance implementing prometheus.Collector
type Exporter struct {
	configs             []config.Config
	kaddrs              map[string]uint64
	enabledConfigsDesc  *prometheus.Desc
	programInfoDesc     *prometheus.Desc
	programAttachedDesc *prometheus.Desc
	programRunTimeDesc  *prometheus.Desc
	programRunCountDesc *prometheus.Desc
	descs               map[string]map[string]*prometheus.Desc
	btfPath             string
}

func New(configs []config.Config, btfPath string) (*Exporter, error) {
	enabledConfigsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "enabled_configs"),
		"The set of enabled configs",
		[]string{"name"},
		nil,
	)

	programInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_info"),
		"Info about ebpf programs",
		[]string{"config", "program", "tag", "id"},
		nil,
	)

	programAttachedDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_attached"),
		"Whether a program is attached",
		[]string{"id"},
		nil,
	)

	programRunTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_run_time_seconds"),
		"How long has the program been executing",
		[]string{"id"},
		nil,
	)

	programRunCountDesc := prometheus.NewDesc(
		prometheus.BuildFQName(prometheusNamespace, "", "ebpf_program_run_count_total"),
		"How many times has the program been executed",
		[]string{"id"},
		nil,
	)

	return &Exporter{
		configs:             configs,
		modules:             map[string]*libbpfgo.Module{},
		kaddrs:              map[string]uint64{},
		enabledConfigsDesc:  enabledConfigsDesc,
		programInfoDesc:     programInfoDesc,
		programAttachedDesc: programAttachedDesc,
		programRunTimeDesc:  programRunTimeDesc,
		programRunCountDesc: programRunCountDesc,
		attachedProgs:       map[string]map[*libbpfgo.BPFProg]bool{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoders,
		btfPath:             btfPath,
		tracingProvider:     tracingProvider,
	}, nil
}
