package securityviolationsprocessor

import "go.opentelemetry.io/collector/component"

type SecurityViolationsConfig struct {
	ServiceName string `mapstructure:"service_name"`
}

func CreateDefaultSecurityViolationsConfig() component.Config {
	return &SecurityViolationsConfig{
		ServiceName: SecurityViolationsProcessorName,
	}
}
