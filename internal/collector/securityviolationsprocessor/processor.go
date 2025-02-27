// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/collector/pdata/pcommon"

	snappy "github.com/eapache/go-xerial-snappy"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

const (
	SecurityViolationsProcessorName = "securityviolationsprocessor"
)

type BodyCompression int64

const (
	None = iota
	Gzip
	Snappy
)

type SecurityViolationsProcessor struct {
	next consumer.Logs
	log  *zap.Logger

	serviceName string
	compression BodyCompression
}

type LogsOption func(*SecurityViolationsProcessor)

func WithLogsLogOption(l zap.Logger) LogsOption {
	return func(p *SecurityViolationsProcessor) {
		p.log = &l
	}
}

func WithCompression(compression BodyCompression) LogsOption {
	return func(p *SecurityViolationsProcessor) {
		p.compression = compression
	}
}

func (p *SecurityViolationsProcessor) Start(_ context.Context, _ component.Host) error {
	p.log.Debug("starting security violations processor")
	return nil
}

func (p *SecurityViolationsProcessor) Shutdown(_ context.Context) error {
	p.log.Debug("shutting down security violations processor")
	return nil
}

func (p *SecurityViolationsProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{
		MutatesData: true,
	}
}

func (p *SecurityViolationsProcessor) ConsumeLogs(ctx context.Context, ld plog.Logs) error {
	return p.processLogs(ctx, ld)
}

func (p *SecurityViolationsProcessor) processLogs(
	_ context.Context,
	ld plog.Logs,
) error {
	p.log.Debug(fmt.Sprintf("processing logs (%d records)", ld.LogRecordCount()))

	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		// resource.attributes contains common dimensions for all the scoped_metrics
		resLog := ld.ResourceLogs().At(i)
		for j := 0; j < resLog.ScopeLogs().Len(); j++ {
			for k := 0; k < resLog.ScopeLogs().At(j).LogRecords().Len(); k++ {
				logRec := resLog.ScopeLogs().At(j).LogRecords().At(k).Body()
				if err := handleCompression(p.compression, logRec); err != nil {
					p.log.Debug(fmt.Sprintf("failed to set log body: %s", err.Error()))
				}
			}
		}
	}

	return nil
}

func handleCompression(compression BodyCompression, logRec pcommon.Value) error {
	switch compression {
	case Gzip:
		var buf bytes.Buffer
		defer buf.Reset()

		gzipWriter, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
		if err != nil {
			return err
		}
		if _, err = gzipWriter.Write([]byte(logRec.Str())); err != nil {
			return errors.New("failed to gzip compress otel log record")
		}

		// ensure gzipWriter is closed and write the footer of the gzip content
		if err = gzipWriter.Close(); err != nil {
			return errors.New("failed to close gzip writer")
		}

		return logRec.FromRaw(buf.Bytes())
	case Snappy:
		logBytes := snappy.Encode([]byte(logRec.Str()))

		return logRec.FromRaw(logBytes)
	default:
		// do nothing
		return nil
	}
}
