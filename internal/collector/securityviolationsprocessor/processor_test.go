// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.
package securityviolationsprocessor

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"

	snappy "github.com/eapache/go-xerial-snappy"
	"github.com/stretchr/testify/require"
)

func TestProcessor_NoCompression(t *testing.T) {
	logger := newLogger(t)

	sp := SecurityViolationsProcessor{
		log: logger,
	}

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	expectedStr := "foo"
	logRecord.Body().SetStr(expectedStr)

	err := sp.ConsumeLogs(context.Background(), logs)
	require.NoError(t, err)

	// should be encoded
	require.Equal(t, pcommon.ValueTypeStr, logRecord.Body().Type())
	require.Equal(t, expectedStr, logRecord.Body().Str())
}

func TestProcessor_GzipCompression(t *testing.T) {
	logger := newLogger(t)

	sp := SecurityViolationsProcessor{
		log:         logger,
		compression: Gzip,
	}

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	expectedStr := "foo"
	logRecord.Body().SetStr(expectedStr)

	err := sp.ConsumeLogs(context.Background(), logs)
	require.NoError(t, err)

	// should be encoded
	require.Equal(t, pcommon.ValueTypeBytes, logRecord.Body().Type())

	// should successfully decode
	buf := bytes.NewBuffer(logRecord.Body().Bytes().AsRaw())
	reader, err := gzip.NewReader(buf)
	require.NoError(t, err)

	result, _ := io.ReadAll(reader)
	require.Equal(t, expectedStr, string(result))
}

func TestProcessor_SnappyCompression(t *testing.T) {
	logger := newLogger(t)

	sp := SecurityViolationsProcessor{
		log:         logger,
		compression: Snappy,
	}

	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecord := scopeLogs.LogRecords().AppendEmpty()

	expectedStr := "foo"
	logRecord.Body().SetStr(expectedStr)

	err := sp.ConsumeLogs(context.Background(), logs)
	require.NoError(t, err)

	// should be encoded
	require.Equal(t, pcommon.ValueTypeBytes, logRecord.Body().Type())

	// should successfully decode
	result, err := snappy.Decode(logRecord.Body().Bytes().AsRaw())
	require.NoError(t, err)
	require.Equal(t, expectedStr, string(result))
}

func newLogger(t *testing.T) *zap.Logger {
	t.Helper()
	logCfg := zap.NewDevelopmentConfig()
	logCfg.OutputPaths = []string{"stdout"}
	logCfg.ErrorOutputPaths = []string{"stderr"}
	logger, err := logCfg.Build()
	require.NoError(t, err)

	return logger
}
