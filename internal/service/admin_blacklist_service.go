package service

import (
	"context"
	"fmt"
	"log"
	"time"

	kafkapkg "central-auth/internal/kafka"
	"central-auth/internal/repository"
)

const adminBlockTTL = time.Hour * 24 * 30 // 30 days — admin blocks are long-lived; downstream Redis TTL must exceed any active token window

// AdminBlacklistService manages global blocks for users, JTIs, and service keys.
//
// On every Block call it:
//  1. Persists the entry to the blacklists table (durable, survives restarts).
//  2. For USER blocks: marks all device_sessions rows revoked=true (audit trail).
//  3. Publishes a BlacklistSyncEvent to the blacklist-sync Kafka topic so all
//     Django instances update their L1 cache within one poll interval (~1 s).
//
// On Unblock it removes the DB entry and publishes a "blacklist.unblock" event so
// Django instances proactively evict from L1 cache; the 60-second TTL provides the
// safety net if the Kafka event is missed.
type AdminBlacklistService struct {
	repo              repository.GlobalBlacklistRepository
	deviceSessionRepo repository.DeviceSessionRepository
	publisher         kafkapkg.EventPublisher
}

// NewAdminBlacklistService constructs an AdminBlacklistService.
func NewAdminBlacklistService(
	repo repository.GlobalBlacklistRepository,
	deviceSessionRepo repository.DeviceSessionRepository,
	publisher kafkapkg.EventPublisher,
) *AdminBlacklistService {
	return &AdminBlacklistService{
		repo:              repo,
		deviceSessionRepo: deviceSessionRepo,
		publisher:         publisher,
	}
}

// Block registers a global block for the given target and fans it out via Kafka.
func (s *AdminBlacklistService) Block(ctx context.Context, targetType repository.BlacklistTargetType, targetValue, reason string) error {
	if err := s.repo.Add(ctx, targetType, targetValue, reason); err != nil {
		return fmt.Errorf("admin blacklist: persist block: %w", err)
	}

	// For USER blocks, revoke all device_sessions rows so the audit table reflects
	// the block immediately — independent of the Kafka fan-out to Django.
	if targetType == repository.TargetTypeUser {
		if err := s.deviceSessionRepo.RevokeAllDevices(ctx, targetValue); err != nil {
			// Non-fatal: Kafka event still propagates the block to Django. Log but continue.
			log.Printf("[WARN] admin blacklist: revoke device sessions kratosID=%s: %v", targetValue, err)
		}
	}

	s.publisher.PublishBlacklistSync(kafkapkg.BlacklistSyncEvent{
		EventType:   "blacklist.sync",
		TargetType:  string(targetType),
		TargetValue: targetValue,
		Reason:      reason,
		ExpiresAt:   time.Now().UTC().Add(adminBlockTTL).Format(time.RFC3339Nano),
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})

	return nil
}

// Unblock removes a global block and notifies Django instances to evict from L1 cache.
func (s *AdminBlacklistService) Unblock(ctx context.Context, targetType repository.BlacklistTargetType, targetValue string) error {
	if err := s.repo.Remove(ctx, targetType, targetValue); err != nil {
		return fmt.Errorf("admin blacklist: remove block: %w", err)
	}

	// Publish unblock so Django L1 caches are evicted proactively.
	// Even if the event is lost, the 60-second TTL ensures the entry expires naturally.
	s.publisher.PublishBlacklistSync(kafkapkg.BlacklistSyncEvent{
		EventType:   "blacklist.unblock",
		TargetType:  string(targetType),
		TargetValue: targetValue,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
	})

	return nil
}
