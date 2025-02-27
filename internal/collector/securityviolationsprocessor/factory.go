// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import (
	"context"
	"fmt"

	"github.com/go-viper/mapstructure/v2"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"

	"github.com/nginx/agent/v3/internal/collector/securityviolationsprocessor/internal/metadata"
)

// nolint: ireturn
func NewFactory() processor.Factory {
	factory := processor.NewFactory(
		metadata.Type,
		CreateDefaultSecurityViolationsConfig,
		processor.WithLogs(CreateSecurityViolationsProcessorFunc, component.StabilityLevelBeta),
	)

	return factory
}

// nolint: ireturn
func CreateSecurityViolationsProcessorFunc(
	_ context.Context,
	_ processor.Settings,
	cfg component.Config,
	logs consumer.Logs,
) (processor.Logs, error) {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

	var convertedConfig SecurityViolationsConfig
	err := mapstructure.Decode(cfg, &convertedConfig)
	if err != nil {
		return nil, err
	}

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	sep := &SecurityViolationsProcessor{
		serviceName: SecurityViolationsProcessorName,
		log:         logger,
		next:        logs,
		compression: convertedConfig.Compression,
	}

	logger.Debug(fmt.Sprintf("create security violation processor (compression=%d)",
		convertedConfig.Compression))

	return sep, nil
}
