//go:build integration

package repository_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"central-auth/internal/repository"

	"github.com/redis/go-redis/v9"
)

func integrationRedisClient(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: 15})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skipf("real Redis unavailable at %s: %v — skipping integration test", addr, err)
	}
	t.Cleanup(func() {
		rdb.FlushDB(context.Background())
		rdb.Close()
	})
	return rdb
}

func TestIntegration_RedisRepo_SaveLogin_WritesAndReads(t *testing.T) {
	rdb := integrationRedisClient(t)
	repo := repository.NewRedisRepository(rdb)
	ctx := context.Background()

	kratosID := "integ-kratos-1"
	deviceID := "integ-device-1"
	wantToken := "hydra-refresh-token-abc"

	if err := repo.SaveLogin(ctx, kratosID, deviceID, wantToken, 5*time.Minute); err != nil {
		t.Fatalf("SaveLogin: %v", err)
	}

	got, err := repo.GetDeviceRefreshToken(ctx, kratosID, deviceID)
	if err != nil {
		t.Fatalf("GetDeviceRefreshToken: %v", err)
	}
	if got != wantToken {
		t.Errorf("token mismatch: want %q, got %q", wantToken, got)
	}
}

func TestIntegration_RedisRepo_LogoutDevice_RemovesToken(t *testing.T) {
	rdb := integrationRedisClient(t)
	repo := repository.NewRedisRepository(rdb)
	ctx := context.Background()

	kratosID := "integ-kratos-2"
	deviceID := "integ-device-logout"

	if err := repo.SaveLogin(ctx, kratosID, deviceID, "logout-token", 5*time.Minute); err != nil {
		t.Fatalf("SaveLogin: %v", err)
	}
	if err := repo.LogoutDevice(ctx, kratosID, deviceID); err != nil {
		t.Fatalf("LogoutDevice: %v", err)
	}

	_, err := repo.GetDeviceRefreshToken(ctx, kratosID, deviceID)
	if err == nil {
		t.Fatal("expected error after LogoutDevice, got nil")
	}
}

func TestIntegration_RedisRepo_LogoutAll_ClearsAllDevices(t *testing.T) {
	rdb := integrationRedisClient(t)
	repo := repository.NewRedisRepository(rdb)
	ctx := context.Background()

	kratosID := "integ-kratos-3"
	devices := []string{"dev-a", "dev-b", "dev-c"}
	for _, d := range devices {
		if err := repo.SaveLogin(ctx, kratosID, d, "token-"+d, 5*time.Minute); err != nil {
			t.Fatalf("SaveLogin %s: %v", d, err)
		}
	}

	if err := repo.LogoutAll(ctx, kratosID); err != nil {
		t.Fatalf("LogoutAll: %v", err)
	}

	for _, d := range devices {
		if _, err := repo.GetDeviceRefreshToken(ctx, kratosID, d); err == nil {
			t.Errorf("device %s: expected token to be cleared after LogoutAll", d)
		}
	}
}

func TestIntegration_RedisRepo_MaxDevices_EvictsOldest(t *testing.T) {
	rdb := integrationRedisClient(t)
	repo := repository.NewRedisRepository(rdb)
	ctx := context.Background()

	kratosID := "integ-kratos-4"
	ttl := 5 * time.Minute

	// Fill exactly MaxDevices slots.
	for i := range int(repository.MaxDevices) {
		d := fmt.Sprintf("device-%d", i)
		if err := repo.SaveLogin(ctx, kratosID, d, "token-"+d, ttl); err != nil {
			t.Fatalf("SaveLogin device %d: %v", i, err)
		}
		// Small sleep so scores differ and eviction order is deterministic.
		time.Sleep(2 * time.Millisecond)
	}

	// A (MaxDevices+1)-th login must succeed; the oldest device is evicted.
	overflow := "device-overflow"
	if err := repo.SaveLogin(ctx, kratosID, overflow, "token-overflow", ttl); err != nil {
		t.Fatalf("SaveLogin overflow: %v", err)
	}

	got, err := repo.GetDeviceRefreshToken(ctx, kratosID, overflow)
	if err != nil {
		t.Fatalf("GetDeviceRefreshToken overflow: %v", err)
	}
	if got != "token-overflow" {
		t.Errorf("overflow token: want %q, got %q", "token-overflow", got)
	}
}
