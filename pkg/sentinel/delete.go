package sentinel

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	insights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights/v2"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

const (
	// fetch TI items to be deleted per this amount
	sentinelDeletePageSize = 5000
)

func (s *Sentinel) CleanupThreatIntel(ctx context.Context, l *logrus.Logger) error {
	logger := l.WithField("module", "sentinel_ti")

	cred, err := azidentity.NewClientSecretCredential(s.creds.TenantID, s.creds.ClientID, s.creds.ClientSecret, nil)
	if err != nil {
		return fmt.Errorf("could not authenticate to MS Sentinel: %v", err)
	}

	tiClient, err := insights.NewThreatIntelligenceIndicatorClient(s.creds.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("could not create TI client: %v", err)
	}

	yesterday := time.Now().AddDate(0, 0, -1)

	hasMorePages := true
	totalDeleted := 0
	pages := 0

	deleted := make(map[string]bool)

	for hasMorePages {
		logger.WithField("page", pages).WithField("total_deleted", totalDeleted).Info("retrieving expired TI indicators")
		pager := tiClient.NewQueryIndicatorsPager(s.creds.ResourceGroup, s.creds.WorkspaceName, insights.ThreatIntelligenceFilteringCriteria{
			IncludeDisabled: to.Ptr(false),
			MaxValidUntil:   to.Ptr(yesterday.Format(time.RFC3339)),
			PageSize:        to.Ptr[int32](sentinelDeletePageSize),
		}, nil)

		if !pager.More() {
			hasMorePages = false
			break
		}

		totalPageDeleted := 0

	retry:
		for pager.More() {
			pages += 1

			items, err := pager.NextPage(ctx)
			if err != nil {
				logger.WithError(err).Debug("could not request more TI items")
				break
			}

			if len(items.Value) == 0 {
				hasMorePages = false
				break
			}

			for _, value := range items.Value {
				ti := value.GetThreatIntelligenceInformation()

				logger.WithField("name", *ti.Name).
					WithField("progress", fmt.Sprintf("%d/%d", totalPageDeleted, len(items.Value))).
					WithField("total_deleted", totalDeleted).
					Debug("deleting TI indicator")

				if _, ok := deleted[*ti.ID]; ok {
					logger.WithField("id", *ti.ID).Warn("encountered TI item which was previously deleted")
				}

				deleteCtx := ctx
				var rawResponse *http.Response
				if logger.Logger.IsLevelEnabled(logrus.TraceLevel) {
					deleteCtx = policy.WithCaptureResponse(ctx, &rawResponse)
				}

				_, err := tiClient.Delete(deleteCtx, s.creds.ResourceGroup, s.creds.WorkspaceName, *ti.Name, nil)
				if err != nil {
					if strings.Contains(err.Error(), "Number of delete requests for subscription ") {
						logger.WithField("id", *ti.ID).Warn("exceeded request rate, waiting 30 seconds")
						time.Sleep(time.Second * 30)
						goto retry
					}

					logger.WithError(err).WithField("id", *ti.ID).Error("could not delete TI indicator")
					continue
				}

				deleted[*ti.ID] = true

				totalDeleted += 1
				totalPageDeleted += 1
			}
		}
	}

	if totalDeleted > 0 {
		logger.WithField("num", totalDeleted).Info("deleted expired TI indicators")
	} else {
		logger.Info("no TI indicators to delete")
	}

	return nil
}
