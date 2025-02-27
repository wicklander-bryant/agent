// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

package securityviolationsprocessor

import "go.opentelemetry.io/collector/component"

// nolint: ireturn
type SecurityViolationsConfig struct {
	ServiceName string          `mapstructure:"service_name"`
	Compression BodyCompression `mapstructure:"compression"`
}

// nolint: ireturn
func CreateDefaultSecurityViolationsConfig() component.Config {
	return &SecurityViolationsConfig{
		ServiceName: SecurityViolationsProcessorName,
		Compression: Snappy,
	}
}
