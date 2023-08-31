package misp

import (
	"errors"
	"github.com/sirupsen/logrus"
)

type MISP struct {
	logger    *logrus.Logger
	baseURL   string
	accessKey string
}

func New(l *logrus.Logger, baseURL, accessKey string) (*MISP, error) {
	if baseURL == "" {
		return nil, errors.New("no base url provided")
	}

	if accessKey == "" {
		return nil, errors.New("no access key provided")
	}

	misp := MISP{
		logger:    l,
		baseURL:   baseURL,
		accessKey: accessKey,
	}

	return &misp, nil
}
