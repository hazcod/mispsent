package main

import (
	"context"
	"flag"
	"github.com/hazcod/crowdstrike2sentinel/config"
	"github.com/hazcod/crowdstrike2sentinel/pkg/misp"
	"github.com/hazcod/crowdstrike2sentinel/pkg/sentinel"
	"github.com/sirupsen/logrus"
	"net/url"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	ctx := context.Background()

	confFile := flag.String("config", "config.yml", "The YAML configuration file.")
	flag.Parse()

	conf := config.Config{}
	if err := conf.Load(*confFile); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("failed to load configuration")
	}

	if err := conf.Validate(); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("invalid configuration")
	}

	logrusLevel, err := logrus.ParseLevel(conf.Log.Level)
	if err != nil {
		logger.WithError(err).Error("invalid log level provided")
		logrusLevel = logrus.InfoLevel
	}
	logger.SetLevel(logrusLevel)

	logger.Info("fetching MISP TI indicators")
	mispClient, err := misp.New(logger, conf.MISP.BaseURL, conf.MISP.AccessKey)
	if err != nil {
		logger.WithError(err).Fatal("could not create MISP client")
	}

	// ms sentinel

	sen, err := sentinel.New(sentinel.Credentials{
		TenantID:       conf.Microsoft.TenantID,
		ClientID:       conf.Microsoft.AppID,
		ClientSecret:   conf.Microsoft.SecretKey,
		SubscriptionID: conf.Microsoft.SubscriptionID,
		ResourceGroup:  conf.Microsoft.ResourceGroup,
		WorkspaceName:  conf.Microsoft.WorkspaceName,
	})
	if err != nil {
		logger.WithError(err).Fatal("could not create sentinel instance")
	}

	logger.Info("cleaning up Sentinel TI")
	if err := sen.CleanupThreatIntel(ctx, logger, 30); err != nil {
		logger.WithError(err).Fatal("could not send to Sentinelm")
	}

	indicators, err := mispClient.FetchIndicators(conf.MISP.DaysToFetch, conf.MISP.TypesToFetch)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch MISP TI indicators")
	}

	mispHostname := conf.MISP.BaseURL
	mispURL, err := url.Parse(mispHostname)
	if err != nil {
		mispHostname = conf.MISP.BaseURL
		logger.WithError(err).WithField("misp_url", conf.MISP.BaseURL).Error("could not parse MISP URL")
	} else {
		mispHostname = mispURL.Hostname()
	}

	if err := sen.SubmitThreatIntel(ctx, logger, conf.Microsoft.ExpiresMonths, mispHostname, indicators); err != nil {
		logger.WithError(err).Fatal("failed to submit indicators")
	}

}
