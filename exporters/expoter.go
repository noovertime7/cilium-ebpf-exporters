package exporters

import (
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/noovertime7/cilium-ebpf-exporters/config"
	"github.com/noovertime7/cilium-ebpf-exporters/decoder"
	"github.com/noovertime7/cilium-ebpf-exporters/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/vishvananda/netlink"
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
			list, err := netlink.LinkList()
			if err != nil {
				return attached, err
			}

			for _, v := range list {
				index := v.Attrs().Index

				sock, err := util.OpenRawSock(index)
				if err != nil {
					return attached, fmt.Errorf("failed to open socket %d: %v", index, err)
				}

				if err := unix.SetsockoptInt(sock, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD()); err != nil {
					return attached, fmt.Errorf("failed to SetsockoptInt socket %d: %v", index, err)
				}
				file := os.NewFile(uintptr(sock), fmt.Sprintf("raw_sock_%s", cfg.Interface))
				if file == nil {
					return attached, fmt.Errorf("failed to open raw_sock_%s", cfg.Interface)
				}

				if err = link.AttachSocketFilter(file, prog); err != nil {
					return attached, fmt.Errorf("failed to attach socket %d: %v", index, err)
				}
			}

			attached[prog] = true
			e.links[cfg.Name] = append(e.links[cfg.Name], l)

		case config.CGroupSkb:
			return attached, fmt.Errorf("cgroup skb attachment not implemented yet")

		default:
			return attached, fmt.Errorf("unsupported program type: %s", cfg.ProgramType)
		}
	}

	return attached, nil
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	addDescs := func(programName string, name string, help string, labels []config.Label) {
		if _, ok := e.descs[programName][name]; !ok {
			labelNames := []string{}

			for _, label := range labels {
				labelNames = append(labelNames, label.Name)
			}

			e.descs[programName][name] = prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, labelNames, nil)
		}

		ch <- e.descs[programName][name]
	}

	ch <- e.enabledConfigsDesc
	ch <- e.programInfoDesc
	ch <- e.programAttachedDesc

	for _, cfg := range e.configs {
		if _, ok := e.descs[cfg.Name]; !ok {
			e.descs[cfg.Name] = map[string]*prometheus.Desc{}
		}

		for _, counter := range cfg.Metrics.Counters {

			addDescs(cfg.Name, counter.Name, counter.Help, counter.Labels)
		}

		for _, histogram := range cfg.Metrics.Histograms {
			addDescs(cfg.Name, histogram.Name, histogram.Help, histogram.Labels[0:len(histogram.Labels)-1])
		}

	}
}

// Collect satisfies prometheus.Collector interface and sends all metrics
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	for _, cfg := range e.configs {
		ch <- prometheus.MustNewConstMetric(e.enabledConfigsDesc, prometheus.GaugeValue, 1, cfg.Name)
	}

	for name, attachments := range e.attachedProgs {
		for program, attached := range attachments {
			info, err := extractProgramInfo(program)
			if err != nil {
				log.Printf("Error extracting program info for %q in config %q: %v", name, name, err)
			}

			id := strconv.Itoa(info.id)

			ch <- prometheus.MustNewConstMetric(e.programInfoDesc, prometheus.GaugeValue, 1, name, name, info.tag, id)

			attachedValue := 0.0
			if attached {
				attachedValue = 1.0
			}

			ch <- prometheus.MustNewConstMetric(e.programAttachedDesc, prometheus.GaugeValue, attachedValue, id)

			statsEnabled, err := bpfStatsEnabled()
			if err != nil {
				log.Printf("Error checking whether bpf stats are enabled: %v", err)
			} else {
				if statsEnabled {
					ch <- prometheus.MustNewConstMetric(e.programRunTimeDesc, prometheus.CounterValue, info.runTime.Seconds(), id)
					ch <- prometheus.MustNewConstMetric(e.programRunCountDesc, prometheus.CounterValue, float64(info.runCount), id)
				}
			}
		}
	}

	e.collectCounters(ch)
	e.collectHistograms(ch)
}

// collectCounters sends all known counters to prometheus
func (e *Exporter) collectCounters(ch chan<- prometheus.Metric) {
	for _, cfg := range e.configs {
		for _, counter := range cfg.Metrics.Counters {
			if counter.PerfEventArray {
				continue
			}

			mapValues, err := e.mapValues(e.modules[cfg.Name], counter.Name, counter.Labels)
			if err != nil {
				log.Printf("Error getting map %q values for metric %q of config %q: %s", counter.Name, counter.Name, cfg.Name, err)
				continue
			}

			aggregatedMapValues := aggregateMapValues(mapValues)

			desc := e.descs[cfg.Name][counter.Name]

			for _, metricValue := range aggregatedMapValues {
				ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue, metricValue.value, metricValue.labels...)
			}
		}
	}
}

// collectHistograms sends all known histograms to prometheus
func (e *Exporter) collectHistograms(ch chan<- prometheus.Metric) {
	for _, cfg := range e.configs {
		for _, histogram := range cfg.Metrics.Histograms {
			skip := false

			histograms := map[string]histogramWithLabels{}

			mapValues, err := e.mapValues(e.modules[cfg.Name], histogram.Name, histogram.Labels)
			if err != nil {
				log.Printf("Error getting map %q values for metric %q of config %q: %s", histogram.Name, histogram.Name, cfg.Name, err)
				continue
			}

			aggregatedMapValues := aggregateMapValues(mapValues)

			// Taking the last label and using int as bucket delimiter, for example:
			//
			// Before:
			// * [sda, read, 1ms] -> 10
			// * [sda, read, 2ms] -> 2
			// * [sda, read, 4ms] -> 5
			//
			// After:
			// * [sda, read] -> {1ms -> 10, 2ms -> 2, 4ms -> 5}
			for _, metricValue := range aggregatedMapValues {
				labels := metricValue.labels[0 : len(metricValue.labels)-1]

				key := fmt.Sprintf("%#v", labels)

				if _, ok := histograms[key]; !ok {
					histograms[key] = histogramWithLabels{
						labels:  labels,
						buckets: map[float64]uint64{},
					}
				}

				leUint, err := strconv.ParseUint(metricValue.labels[len(metricValue.labels)-1], 0, 64)
				if err != nil {
					log.Printf("Error parsing float value for bucket %#v in map %q of config %q: %s", metricValue.labels, histogram.Name, cfg.Name, err)
					skip = true
					break
				}

				histograms[key].buckets[float64(leUint)] = uint64(metricValue.value)
			}

			if skip {
				continue
			}

			desc := e.descs[cfg.Name][histogram.Name]

			for _, histogramSet := range histograms {
				buckets, count, sum, err := transformHistogram(histogramSet.buckets, histogram)
				if err != nil {
					log.Printf("Error transforming histogram for metric %q in config %q: %s", histogram.Name, cfg.Name, err)
					continue
				}

				ch <- prometheus.MustNewConstHistogram(desc, count, sum, buckets, histogramSet.labels...)
			}
		}
	}
}

func aggregateMapValues(values []metricValue) []aggregatedMetricValue {
	aggregated := []aggregatedMetricValue{}
	mapping := map[string]*aggregatedMetricValue{}

	for _, value := range values {
		key := strings.Join(value.labels, "|")

		if existing, ok := mapping[key]; !ok {
			mapping[key] = &aggregatedMetricValue{
				labels: value.labels,
				value:  value.value,
			}
		} else {
			existing.value += value.value
		}
	}

	for _, value := range mapping {
		aggregated = append(aggregated, *value)
	}

	return aggregated
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
