package metrics

import (
	"context"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/otel/trace"
)

func initTracer() (trace.Tracer, func()) {
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		panic(err)
	}

	tracerProvider := trace.NewTracerProvider(
		trace.WithSampler(trace.AlwaysSample()),
		trace.WithBatcher(exporter),
		trace.WithResource(resource.Default()),
	)
	otel.SetTracerProvider(tracerProvider)

	return otel.Tracer("your-service-name"), func() {
		_ = tracerProvider.Shutdown(context.Background())
	}
}
