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

	// Attach all programs in the collection
	attachments, err := e.attachProgram(cfg, coll)
	if err != nil {
		return err
	}

	err = validateMaps(coll, cfg)
	if err != nil {
		return fmt.Errorf("error validating maps for config %q: %v", cfg.Name, err)
	}

	e.attachedProgs[cfg.Name] = attachments
	e.modules[cfg.Name] = coll

	return nil
}

func (e *Exporter) attachProgram(cfg config.Config, coll *ebpf.Collection) (map[*ebpf.Program]bool, error) {
	attached := map[*ebpf.Program]bool{}

	for progName, prog := range coll.Programs {
		var l link.Link
		var err error

		switch cfg.ProgramType {
		case config.KProbe:
			// 尝试配置中定义的所有可能的函数名
			var lastErr error
			for _, kaddr := range cfg.Kaddrs {
				l, err = link.Kprobe(kaddr, prog, nil)
				if err == nil {
					attached[prog] = true
					e.links[cfg.Name] = append(e.links[cfg.Name], l)
					break
				}
				lastErr = err
			}
			if err != nil {
				attached[prog] = false
				return attached, fmt.Errorf("failed to attach kprobe to any of the specified functions: %v", lastErr)
			}

		case config.TracePoint:
			parts := strings.Split(progName, "/")
			if len(parts) != 2 {
				attached[prog] = false
				return attached, fmt.Errorf("invalid tracepoint format %q, expected category/name", progName)
			}
			l, err = link.Tracepoint(parts[0], parts[1], prog, nil)
			if err != nil {
				attached[prog] = false
				return attached, fmt.Errorf("failed to attach tracepoint: %v", err)
			}
			attached[prog] = true
			e.links[cfg.Name] = append(e.links[cfg.Name], l)

		case config.SocketFilter:
			return attached, fmt.Errorf("socket filter attachment not implemented yet")

		case config.CGroupSkb:
			return attached, fmt.Errorf("cgroup skb attachment not implemented yet")

		default:
			return attached, fmt.Errorf("unsupported program type: %s", cfg.ProgramType)
		}
	}

	return attached, nil
}

func validateMaps(module *ebpf.Collection, cfg config.Config) error {
	maps := []string{}

	for _, counter := range cfg.Metrics.Counters {
		if counter.Name != "" && !counter.PerfEventArray {
			maps = append(maps, counter.Name)
		}
	}

	for _, histogram := range cfg.Metrics.Histograms {
		if histogram.Name != "" {
			maps = append(maps, histogram.Name)
		}
	}

	for _, name := range maps {
		m, ok := module.Maps[name]
		if !ok {
			return fmt.Errorf("failed to get map %q", name)
		}

		valueSize := m.ValueSize()
		if valueSize != 8 {
			return fmt.Errorf("value size for map %q is not expected 8 bytes (u64), it is %d bytes", name, valueSize)
		}
	}

	return nil
}
