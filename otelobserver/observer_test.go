package otelobserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"go.opentelemetry.io/otel"
	logapi "go.opentelemetry.io/otel/log"
	lognoop "go.opentelemetry.io/otel/log/noop"
	"go.opentelemetry.io/otel/metric"
)

func TestGlobalProvidersAndObserve(t *testing.T) {
	capture := &capturingLogger{Logger: lognoop.NewLoggerProvider().Logger("test")}
	observer, err := New(Config{LoggerProvider: fixedLoggerProvider{
		LoggerProvider: lognoop.NewLoggerProvider(), logger: capture,
	}})
	if err != nil {
		t.Fatal(err)
	}
	observer.Observe(context.Background(), credbound.Operation{Name: "auth.test", Outcome: "success", Duration: 25 * time.Millisecond})
	observer.Observe(context.Background(), credbound.Operation{Name: "auth.test", Outcome: "error", Duration: 25 * time.Millisecond})
	if len(capture.records) != 2 || capture.records[0].Severity() != logapi.SeverityInfo || capture.records[1].Severity() != logapi.SeverityError {
		t.Fatalf("OTEL log records = %#v", capture.records)
	}
	if capture.records[0].EventName() != "credbound.operation" || capture.records[0].Body().AsString() != "auth.test" || capture.records[0].AttributesLen() != 2 {
		t.Fatalf("OTEL log content = %#v", capture.records[0])
	}
}

func TestInstrumentCreationFailures(t *testing.T) {
	base := otel.GetMeterProvider().Meter("test")
	counterFailure := failingMeter{Meter: base, counterErr: errors.New("counter failed")}
	if _, err := New(Config{MeterProvider: fixedMeterProvider{meter: counterFailure}}); err == nil || err.Error() != "counter failed" {
		t.Fatalf("counter failure = %v", err)
	}
	histogramFailure := failingMeter{Meter: base, histogramErr: errors.New("histogram failed")}
	if _, err := New(Config{MeterProvider: fixedMeterProvider{meter: histogramFailure}}); err == nil || err.Error() != "histogram failed" {
		t.Fatalf("histogram failure = %v", err)
	}
}

type fixedMeterProvider struct {
	metric.MeterProvider
	meter metric.Meter
}

func (p fixedMeterProvider) Meter(string, ...metric.MeterOption) metric.Meter { return p.meter }

type failingMeter struct {
	metric.Meter
	counterErr   error
	histogramErr error
}

type fixedLoggerProvider struct {
	logapi.LoggerProvider
	logger logapi.Logger
}

func (p fixedLoggerProvider) Logger(string, ...logapi.LoggerOption) logapi.Logger { return p.logger }

type capturingLogger struct {
	logapi.Logger
	records []logapi.Record
}

func (l *capturingLogger) Emit(_ context.Context, record logapi.Record) {
	l.records = append(l.records, record.Clone())
}

func (m failingMeter) Int64Counter(name string, options ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	if m.counterErr != nil {
		return nil, m.counterErr
	}
	return m.Meter.Int64Counter(name, options...)
}

func (m failingMeter) Float64Histogram(name string, options ...metric.Float64HistogramOption) (metric.Float64Histogram, error) {
	if m.histogramErr != nil {
		return nil, m.histogramErr
	}
	return m.Meter.Float64Histogram(name, options...)
}
