// Package otelobserver implements the credbound.Observer port with
// OpenTelemetry: every observed operation becomes a span, a
// "credbound.operations" counter increment, a
// "credbound.operation.duration" histogram sample and a log record, all
// attributed with the operation name and outcome. Operation records carry
// no secrets, so the telemetry is safe to export.
//
// Wire it into credbound.Config.Observer:
//
//	observer, err := otelobserver.New(otelobserver.Config{})
//
// A zero Config uses the process-global OTEL providers.
package otelobserver

import (
	"context"
	"time"

	"github.com/deepteams/credbound"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	logapi "go.opentelemetry.io/otel/log"
	logglobal "go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "github.com/deepteams/credbound"

// Config selects the OpenTelemetry providers to emit through. Each nil
// field falls back to the corresponding process-global provider.
type Config struct {
	// TracerProvider produces the per-operation spans. Defaults to
	// otel.GetTracerProvider().
	TracerProvider trace.TracerProvider
	// MeterProvider backs the operation counter and duration histogram.
	// Defaults to otel.GetMeterProvider().
	MeterProvider metric.MeterProvider
	// LoggerProvider receives one log record per operation. Defaults to
	// the global log provider.
	LoggerProvider logapi.LoggerProvider
}

// Observer forwards credbound.Operation records to OpenTelemetry traces,
// metrics and logs. It is safe for concurrent use and implements
// credbound.Observer.
type Observer struct {
	tracer   trace.Tracer
	counter  metric.Int64Counter
	duration metric.Float64Histogram
	logger   logapi.Logger
}

// New builds an Observer, creating its instruments on the configured (or
// global) providers. It fails only when an instrument cannot be created.
func New(config Config) (*Observer, error) {
	if config.TracerProvider == nil {
		config.TracerProvider = otel.GetTracerProvider()
	}
	if config.MeterProvider == nil {
		config.MeterProvider = otel.GetMeterProvider()
	}
	if config.LoggerProvider == nil {
		config.LoggerProvider = logglobal.GetLoggerProvider()
	}
	meter := config.MeterProvider.Meter(instrumentationName)
	counter, err := meter.Int64Counter("credbound.operations", metric.WithDescription("Number of Credbound operations"))
	if err != nil {
		return nil, err
	}
	duration, err := meter.Float64Histogram("credbound.operation.duration", metric.WithUnit("s"), metric.WithDescription("Credbound operation latency"))
	if err != nil {
		return nil, err
	}
	return &Observer{
		tracer: config.TracerProvider.Tracer(instrumentationName), counter: counter, duration: duration,
		logger: config.LoggerProvider.Logger(instrumentationName),
	}, nil
}

// Observe records one completed operation: a span back-dated by the
// operation's duration, a counter increment, a histogram sample and a log
// record (error severity for the "error" outcome).
func (o *Observer) Observe(ctx context.Context, operation credbound.Operation) {
	attributes := []attribute.KeyValue{
		attribute.String("credbound.operation", operation.Name),
		attribute.String("credbound.outcome", operation.Outcome),
	}
	now := time.Now()
	_, span := o.tracer.Start(ctx, operation.Name, trace.WithTimestamp(now.Add(-operation.Duration)))
	span.SetAttributes(attributes...)
	span.End(trace.WithTimestamp(now))
	o.counter.Add(ctx, 1, metric.WithAttributes(attributes...))
	o.duration.Record(ctx, operation.Duration.Seconds(), metric.WithAttributes(attributes...))
	severity := logapi.SeverityInfo
	if operation.Outcome == "error" {
		severity = logapi.SeverityError
	}
	var record logapi.Record
	record.SetTimestamp(now)
	record.SetEventName("credbound.operation")
	record.SetSeverity(severity)
	record.SetBody(attribute.StringValue(operation.Name))
	record.AddAttributes(attributes...)
	o.logger.Emit(ctx, record)
}

var _ credbound.Observer = (*Observer)(nil)
