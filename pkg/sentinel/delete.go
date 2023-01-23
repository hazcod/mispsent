package sentinel

import (
	"context"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	insights "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/securityinsights/armsecurityinsights/v2"
	"github.com/sirupsen/logrus"
	"time"
)

func (s *Sentinel) CleanupThreatIntel(ctx context.Context, l *logrus.Logger, retentionDays uint32) error {
	logger := l.WithField("module", "sentinel_ti")

	cred, err := azidentity.NewClientSecretCredential(s.creds.TenantID, s.creds.ClientID, s.creds.ClientSecret, nil)
	if err != nil {
		return fmt.Errorf("could not authenticate to MS Sentinel: %v", err)
	}

	tiClient, err := insights.NewThreatIntelligenceIndicatorClient(s.creds.SubscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("could not create TI client: %v", err)
	}

	tomorrow := time.Now().AddDate(0, 0, -1)

	logger.Info("retrieving expired TI indicators")
	pager := tiClient.NewQueryIndicatorsPager(s.creds.ResourceGroup, s.creds.WorkspaceName, insights.ThreatIntelligenceFilteringCriteria{
		IncludeDisabled: to.Ptr(true),
		MaxValidUntil:   to.Ptr(tomorrow.Format(time.RFC3339)),
		PageSize:        to.Ptr[int32](1000),
	}, nil)

	totalDeleted := 0

	for pager.More() {
		items, err := pager.NextPage(ctx)
		if err != nil {
			logger.WithError(err).Error("could not request more TI items")
			break
		}

		for _, value := range items.Value {
			ti := value.GetThreatIntelligenceInformation()

			totalDeleted += 1

			logger.WithField("id", *ti.ID).WithField("progress", fmt.Sprintf("%d/%d", totalDeleted, len(items.Value))).
				Debug("deleting TI indicator")

			if _, err := tiClient.Delete(ctx, s.creds.ResourceGroup, s.creds.WorkspaceName, *ti.Name, nil); err != nil {
				logger.WithError(err).WithField("id", *ti.ID).Error("could not delete TI indicator")
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
