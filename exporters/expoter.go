package exporters

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/decoder"
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
	decoders            *decoder.Set

	modules       map[string]*ebpf.Collection
	attachedProgs map[string]map[*ebpf.Program]bool
	links         map[string][]link.Link
}

func NewExporter(configs []config.Config, btfPath string) (*Exporter, error) {
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

	decoders, err := decoder.NewSet()
	if err != nil {
		return nil, fmt.Errorf("error creating decoder set: %v", err)
	}

	return &Exporter{
		configs:             configs,
		modules:             map[string]*ebpf.Collection{},
		kaddrs:              map[string]uint64{},
		enabledConfigsDesc:  enabledConfigsDesc,
		programInfoDesc:     programInfoDesc,
		programAttachedDesc: programAttachedDesc,
		programRunTimeDesc:  programRunTimeDesc,
		programRunCountDesc: programRunCountDesc,
		attachedProgs:       map[string]map[*ebpf.Program]bool{},
		links:               map[string][]link.Link{},
		descs:               map[string]map[string]*prometheus.Desc{},
		decoders:            decoders,
		btfPath:             btfPath,
	}, nil
}

func (e *Exporter) Attach() error {
	for _, cfg := range e.configs {
		err := e.attachConfig(cfg)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Exporter) attachConfig(cfg config.Config) error {
	if _, ok := e.modules[cfg.Name]; ok {
		return fmt.Errorf("multiple configs with name %q", cfg.Name)
	}

	// Load the pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec(cfg.BPFPath)
	if err != nil {
		return fmt.Errorf("failed to load BPF spec for config %q: %v", cfg.Name, err)
	}

	// Load the collection with BTF support
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 2097152,
		},
	}

	// Set BTF file if specified
	if e.btfPath != "" {
		// Load BTF spec from file
		btfSpec, err := btf.LoadSpec(e.btfPath)
		if err != nil {
			return fmt.Errorf("failed to load BTF spec: %v", err)
		}
		opts.Programs.KernelTypes = btfSpec
	}

	// Create the collection
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection for config %q: %v", cfg.Name, err)
	}

	// Store the collection
	e.modules[cfg.Name] = coll
	e.attachedProgs[cfg.Name] = make(map[*ebpf.Program]bool)

	// Attach all programs in the collection
	for progName, prog := range coll.Programs {
		if err := e.attachProgram(cfg, progName, prog); err != nil {
			return fmt.Errorf("failed to attach program %q in config %q: %v", progName, cfg.Name, err)
		}
		e.attachedProgs[cfg.Name][prog] = true
	}

	return nil
}

func (e *Exporter) attachProgram(cfg config.Config, progName string, prog *ebpf.Program) error {
	var l link.Link
	var err error

	switch cfg.ProgramType {
	case config.KProbe:
		l, err = link.Kprobe(progName, prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach kprobe: %v", err)
		}

	case config.TracePoint:
		// 对于 tracepoint，程序名称格式应该是 "category/name"
		parts := strings.Split(progName, "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid tracepoint format %q, expected category/name", progName)
		}
		l, err = link.Tracepoint(parts[0], parts[1], prog, nil)
		if err != nil {
			return fmt.Errorf("failed to attach tracepoint: %v", err)
		}

	case config.SocketFilter:
		// Socket filter 实现...
		return fmt.Errorf("socket filter attachment not implemented yet")

	case config.CGroupSkb:
		// CGroup SKB 实现...
		return fmt.Errorf("cgroup skb attachment not implemented yet")

	default:
		return fmt.Errorf("unsupported program type: %s", cfg.ProgramType)
	}

	e.links[cfg.Name] = append(e.links[cfg.Name], l)
	return nil
}
