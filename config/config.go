package config

import (
	"fmt"
	validator "github.com/asaskevich/govalidator"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"
	"os"
)

const (
	defaultLogLevel      = "INFO"
	defaultExpiresMonths = 6
)

var (
	defaultMispTypesToFetch = []string{"ip-dst", "hostname", "domain", "sha256"}
)

type Config struct {
	Log struct {
		Level string `yaml:"level" env:"LOG_LEVEL"`
	} `yaml:"log"`

	MISP struct {
		BaseURL      string   `yaml:"base_url" env:"MISP_BASE_URL" valid:"url"`
		AccessKey    string   `yaml:"access_key" env:"MISP_ACCESS_KEY" valid:"minstringlength(3)"`
		DaysToFetch  uint32   `yaml:"days_to_fetch" env:"MISP_DAYS_TO_FETCH"`
		TypesToFetch []string `yaml:"types_to_fetch" env:"MISP_TYPES_FETCH"`
	} `yaml:"misp"`

	Sentinel struct {
		AppID          string `yaml:"app_id" env:"MS_APP_ID" valid:"minstringlength(3)"`
		SecretKey      string `yaml:"secret_key" env:"MS_SECRET_KEY" valid:"minstringlength(3)"`
		TenantID       string `yaml:"tenant_id" env:"MS_TENANT_ID" valid:"minstringlength(3)"`
		SubscriptionID string `yaml:"subscription_id" env:"MS_SUB_ID" valid:"minstringlength(3)"`
		ResourceGroup  string `yaml:"resource_group" env:"MS_RES_GROUP" valid:"minstringlength(3)"`
		WorkspaceName  string `yaml:"workspace_name" env:"MS_WS_NAME" valid:"minstringlength(3)"`
		ExpiresMonths  int    `yaml:"expires_months" env:"MS_EXPIRES_MONTHS"`
	} `yaml:"mssentinel"`
}

func (c *Config) Validate() error {
	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}

	if c.Sentinel.ExpiresMonths == 0 {
		c.Sentinel.ExpiresMonths = defaultExpiresMonths
	}

	if len(c.MISP.TypesToFetch) == 0 {
		c.MISP.TypesToFetch = defaultMispTypesToFetch
	}

	if valid, err := validator.ValidateStruct(c); !valid || err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	return nil
}

func (c *Config) Load(path string) error {
	if path != "" {
		configBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to load configuration file at '%s': %v", path, err)
		}

		if err = yaml.Unmarshal(configBytes, c); err != nil {
			return fmt.Errorf("failed to parse configuration: %v", err)
		}
	}

	if err := envconfig.Process("", c); err != nil {
		return fmt.Errorf("could not load environment: %v", err)
	}

	return nil
}
