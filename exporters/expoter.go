package exporters

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/decoder"
	"github.com/noovertime7/cilium-ebpf-exporters/util"
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

// MapsHandler is a debug handler to print raw values of kernel maps
func (e *Exporter) MapsHandler(w http.ResponseWriter, r *http.Request) {
	maps, err := e.exportMaps()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Add("Content-type", "text/plain")
		if _, err = fmt.Fprintf(w, "%s\n", err); err != nil {
			log.Printf("Error returning error to client %q: %s", r.RemoteAddr, err)
			return
		}
		return
	}

	w.Header().Add("Content-type", "text/plain")

	buf := []byte{}

	for cfg, maps := range maps {
		buf = append(buf, fmt.Sprintf("## Config: %s\n\n", cfg)...)

		for name, m := range maps {
			buf = append(buf, fmt.Sprintf("### Map: %s\n\n", name)...)

			buf = append(buf, "```\n"...)
			for _, row := range m {
				buf = append(buf, fmt.Sprintf("%#v (labels: %v) -> %.0f\n", row.raw, row.labels, row.value)...)
			}
			buf = append(buf, "```\n\n"...)
		}
	}

	if _, err = w.Write(buf); err != nil {
		log.Printf("Error returning map contents to client %q: %s", r.RemoteAddr, err)
	}
}

func (e Exporter) exportMaps() (map[string]map[string][]metricValue, error) {
	maps := map[string]map[string][]metricValue{}

	for _, cfg := range e.configs {
		module := e.modules[cfg.Name]
		if module == nil {
			return nil, fmt.Errorf("module for config %q is not attached", cfg.Name)
		}

		if _, ok := maps[cfg.Name]; !ok {
			maps[cfg.Name] = map[string][]metricValue{}
		}

		metricMaps := map[string][]config.Label{}

		for _, counter := range cfg.Metrics.Counters {
			if counter.Name != "" {
				metricMaps[counter.Name] = counter.Labels
			}
		}

		for _, histogram := range cfg.Metrics.Histograms {
			if histogram.Name != "" {
				metricMaps[histogram.Name] = histogram.Labels
			}
		}

		for name, labels := range metricMaps {
			metricValues, err := e.mapValues(e.modules[cfg.Name], name, labels)
			if err != nil {
				return nil, fmt.Errorf("error getting values for map %q of config %q: %s", name, cfg.Name, err)
			}

			maps[cfg.Name][name] = metricValues
		}
	}

	return maps, nil
}

func (e *Exporter) mapValues(coll *ebpf.Collection, name string, labels []config.Label) ([]metricValue, error) {
	m, ok := coll.Maps[name]
	if !ok {
		return nil, fmt.Errorf("failed to retrieve map %q", name)
	}
	metricValues, err := readMapValues(m, labels)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve map %q: %v", name, err)
	}

	for i, mv := range metricValues {
		raw := mv.raw
		// If there are no labels, assume a single key of uint32(0)
		if len(labels) == 0 && bytes.Equal(mv.raw, []byte{0x0, 0x0, 0x0, 0x0}) {
			metricValues[i].labels = []string{}
			continue
		}

		metricValues[i].labels, err = e.decoders.DecodeLabels(raw, name, labels)
		if err != nil {
			if errors.Is(err, decoder.ErrSkipLabelSet) {
				continue
			}

			return nil, err
		}
	}

	return metricValues, nil

}

func readMapValues(ebpfMap *ebpf.Map, labels []config.Label) ([]metricValue, error) {
	metricValues := []metricValue{}

	var key []byte
	var value uint64

	// 使用 Iterate 来遍历 map
	iter := ebpfMap.Iterate()
	for iter.Next(&key, &value) {
		mv := metricValue{
			raw:   make([]byte, len(key)),
			value: float64(value),
		}
		// 复制 key 数据
		copy(mv.raw, key)
		metricValues = append(metricValues, mv)
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("error iterating map: %v", err)
	}

	return metricValues, nil
}

// Assuming counter's value type is always u64
func decodeValue(value []byte) float64 {
	return float64(util.GetHostByteOrder().Uint64(value))
}

// metricValue is a row in a kernel map
type metricValue struct {
	// raw is a raw key value provided by kernel
	raw []byte
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}

// aggregatedMetricValue is a value after aggregation of equal label sets
type aggregatedMetricValue struct {
	// labels are decoded from the raw key
	labels []string
	// value is the kernel map value
	value float64
}
