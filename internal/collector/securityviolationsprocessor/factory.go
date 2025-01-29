// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"

	"github.com/nginx/agent/v3/internal/collector/securityviolationsprocessor/internal/metadata"
)

// nolint: ireturn
func NewFactory() processor.Factory {
	return processor.NewFactory(
		metadata.Type,
		CreateDefaultSecurityViolationsConfig,
		processor.WithLogs(CreateSecurityViolationsProcessorFunc, component.StabilityLevelBeta),
	)
}
func CreateSecurityViolationsProcessorFunc(
	_ context.Context,
	_ processor.Settings,
	_ component.Config,
	logs consumer.Logs,
) (processor.Logs, error) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

	logger, err := config.Build()
	if err != nil {
		// TODO: Shouldn't panic
		panic(err)
	}
	sep := &SecurityViolationsProcessor{
		log:  logger,
		next: logs,
	}

	return sep, nil
}
