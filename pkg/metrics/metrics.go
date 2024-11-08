package metrics

import (
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"log"
	"net/http"
)

const (
	MeterName = "vArmor"
)

type MetricsModule struct {
	meter   metric.Meter
	Enabled bool
	log     logr.Logger
}

func NewMetricsModule(log logr.Logger, enabled bool) *MetricsModule {
	exporter, err := prometheus.New()
	if err != nil {
		log.Error(err, "failed to create Prometheus exporter")
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	meter := provider.Meter(MeterName)
	if enabled == true {
		go func() {
			log.Info("Serving metrics at :8081/metrics")
			http.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(":8081", nil)
			if err != nil {
				log.Error(err, "failed to start metrics server")
			}
		}()
	}

	return &MetricsModule{
		meter:   meter,
		Enabled: enabled,
	}
}
func (m *MetricsModule) RegisterInt64Counter(name string, description string) metric.Int64Counter {
	counter, err := m.meter.Int64Counter(name, metric.WithDescription(description))
	if err != nil {
		m.log.Error(err, "failed to create counter")
	}
	return counter
}
func (m *MetricsModule) RegisterFloat64Counter(name string, description string) metric.Float64Counter {
	counter, err := m.meter.Float64Counter(name, metric.WithDescription(description))
	if err != nil {
		m.log.Error(err, "failed to create counter")
	}
	return counter
}

func (m *MetricsModule) RegisterGauge(name string, description string) metric.Float64Gauge {
	gauge, err := m.meter.Float64Gauge(name, metric.WithDescription(description))
	if err != nil {
		log.Fatalf("failed to create gauge: %v", err)
	}
	return gauge
}

func (m *MetricsModule) RegisterFloat64Gauge(name string, description string) metric.Float64Gauge {
	gauge, err := m.meter.Float64Gauge(name, metric.WithDescription(description))
	if err != nil {
		log.Fatalf("failed to create gauge: %v", err)
	}
	return gauge
}
func (m *MetricsModule) RegisterFloat64ObservableGauge(name string, options ...metric.Float64ObservableGaugeOption) metric.Float64ObservableGauge {
	gauge, err := m.meter.Float64ObservableGauge(name, options...)
	if err != nil {
		log.Fatalf("failed to create gauge: %v", err)
	}
	return gauge
}
func (m *MetricsModule) RegisterHistogram(name string, description string, buckets ...float64) metric.Float64Histogram {
	histogram, err := m.meter.Float64Histogram(name, metric.WithDescription(description), metric.WithExplicitBucketBoundaries(buckets...))
	if err != nil {
		log.Fatalf("failed to create histogram: %v", err)
	}
	return histogram
}
