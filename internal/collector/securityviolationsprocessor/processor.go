package securityviolationsprocessor

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

const (
	SecurityViolationsProcessorName = "securityviolationsprocessor"

	stringValPrefix    = `string_value:"`
	stringValPrefixLen = len(stringValPrefix)
	logSplitDelim      = "\n"
)

type SecurityViolationsProcessor struct {
	log         *zap.Logger
	serviceName string

	next consumer.Logs
}

type LogsOption func(*SecurityViolationsProcessor)

func WithLogsLogOption(l zap.Logger) LogsOption {
	return func(p *SecurityViolationsProcessor) {
		p.log = &l
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
	ctx context.Context,
	ld plog.Logs,
) error {
	p.log.Debug(fmt.Sprintf("processing logs (%v records)", ld.LogRecordCount()))

	var buf bytes.Buffer

	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		// resource.attributes contains common dimensions for all the scoped_metrics
		resLog := ld.ResourceLogs().At(i)
		for j := 0; j < resLog.ScopeLogs().Len(); j++ {
			for k := 0; k < resLog.ScopeLogs().At(j).LogRecords().Len(); k++ {
				logRec := resLog.ScopeLogs().At(j).LogRecords().At(k).Body()

				gzipWriter, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
				if err != nil {
					return err
				}

				_, err = gzipWriter.Write(logRec.Bytes().AsRaw())
				if err != nil {
					return errors.New("failed to gzip compress otel log record")
				}

				// ensure gzipWriter is closed and write the footer of the gzip content
				err = gzipWriter.Close()
				if err != nil {
					return errors.New("failed to close gzip writer")
				}

				// set the log bytes to the gzip compressed bytes and reset teh buffer
				logRec.SetEmptyBytes()
				logRec.FromRaw(buf.Bytes())
				buf.Reset()
			}
		}
	}

	return nil
}
