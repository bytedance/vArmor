package metrics

import (
	"context"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

const (
	MeterName = "vArmor"
)

type Metrics struct {
	meter metric.Meter
}

func NewMetrics() *Metrics {
	provider := otel.GetMeterProvider()
	meter := provider.Meter(MeterName)
	return &Metrics{meter: meter}
}

func (m *Metrics) RecordCounter(name string, value int64) {
	counter := metric.Must(m.meter).NewInt64Counter(name)
	counter.Add(context.Background(), value)
}

func (m *Metrics) RecordHistogram(name string, value float64) {
	histogram := metric.Must(m.meter).NewFloat64Histogram(name)
	histogram.Record(context.Background(), value)
}
