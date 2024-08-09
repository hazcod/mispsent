package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hazcod/crowdstrike2sentinel/config"
	"github.com/hazcod/crowdstrike2sentinel/pkg/misp"
	"github.com/hazcod/crowdstrike2sentinel/pkg/sentinel"
	"github.com/sirupsen/logrus"
	"net/url"
	"sync"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	ctx := context.Background()

	confFile := flag.String("config", "", "The YAML configuration file.")
	flag.Parse()

	conf := config.Config{}
	if err := conf.Load(logger, *confFile); err != nil {
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

	// ---

	taskWg := sync.WaitGroup{}
	errorChann := make(chan error)
	/*
		taskWg.Add(1)
		go func() {
			logger.Info("cleaning up Sentinel TI")

			if err := sen.CleanupThreatIntel(ctx, logger); err != nil {
				errorChann <- fmt.Errorf("could not clean up threat intel: %w", err)
			}

			taskWg.Done()
		}()
	*/
	// fetch TI indicator from MISP

	taskWg.Add(1)
	go func() {
		logger.Info("fetching indicators from MISP")
		indicators, err := mispClient.FetchIndicators(conf.MISP.DaysToFetch, conf.MISP.TypesToFetch)
		if err != nil {
			errorChann <- fmt.Errorf("could not fetch MISP TI indicators: %w", err)
		}

		// submit threat intelligence to ms sentinel

		logger.WithField("total", len(indicators)).Info("submitting MISP indicators to MS Sentinel")
		if err := sen.SubmitThreatIntel(ctx, logger, uint16(conf.Sentinel.ExpiresMonths), mispHostname, indicators); err != nil {
			errorChann <- fmt.Errorf("failed to submit indicators: %w", err)
		}

		taskWg.Done()
	}()

	// wait for work to finish
	doneChan := make(chan struct{})
	go func() {
		taskWg.Wait()
		close(doneChan)
	}()

	logger.Info("waiting for tasks to finish")
	select {
	case err := <-errorChann:
		logger.WithError(err).Fatal("failed")
	case <-doneChan:
		logger.Info("finished tasks")
	}

	// program finish

	logger.Info("submitted all TI to Sentinel")
}
