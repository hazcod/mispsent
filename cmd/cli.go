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

	confFile := flag.String("config", "", "The YAML configuration file.")
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

	// create misp client

	logger.Info("fetching MISP TI indicators")
	mispClient, err := misp.New(logger, conf.MISP.BaseURL, conf.MISP.AccessKey)
	if err != nil {
		logger.WithError(err).Fatal("could not create MISP client")
	}

	mispHostname := conf.MISP.BaseURL
	mispURL, err := url.Parse(mispHostname)
	if err != nil {
		mispHostname = conf.MISP.BaseURL
		logger.WithError(err).WithField("misp_url", conf.MISP.BaseURL).Error("could not parse MISP URL")
	} else {
		mispHostname = mispURL.Hostname()
	}

	// create ms sentinel client

	sen, err := sentinel.New(sentinel.Credentials{
		TenantID:       conf.Sentinel.TenantID,
		ClientID:       conf.Sentinel.AppID,
		ClientSecret:   conf.Sentinel.SecretKey,
		SubscriptionID: conf.Sentinel.SubscriptionID,
		ResourceGroup:  conf.Sentinel.ResourceGroup,
		WorkspaceName:  conf.Sentinel.WorkspaceName,
	})
	if err != nil {
		logger.WithError(err).Fatal("could not create sentinel instance")
	}

	if conf.Sentinel.ExpiresMonths > 0 {
		logger.WithField("expires_months", conf.Sentinel.ExpiresMonths).Info("cleaning up Sentinel TI")

		if err := sen.CleanupThreatIntel(ctx, logger, 30); err != nil {
			logger.WithError(err).Fatal("could not send to Sentinelm")
		}
	} else {
		logger.Info("skipping TI cleanup since expires_month is set to 0")
	}

	// fetch TI indicator from MISP

	logger.Info("fetching indicators from MISP")
	indicators, err := mispClient.FetchIndicators(conf.MISP.DaysToFetch, conf.MISP.TypesToFetch)
	if err != nil {
		logger.WithError(err).Fatal("could not fetch MISP TI indicators")
	}

	// submit threat intelligence to ms sentinel

	logger.WithField("total", len(indicators)).Info("submitting MISP indicators to MS Sentinel")
	if err := sen.SubmitThreatIntel(ctx, logger, uint16(conf.Sentinel.ExpiresMonths), mispHostname, indicators); err != nil {
		logger.WithError(err).Fatal("failed to submit indicators")
	}

	// program finish

	logger.Info("submitted all TI to Sentinel")
}
