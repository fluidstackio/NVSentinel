// Copyright (c) 2025, NVIDIA CORPORATION.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/nvidia/nvsentinel/data-models/pkg/model"
	"github.com/nvidia/nvsentinel/data-models/pkg/protos"
	"github.com/nvidia/nvsentinel/platform-connectors/pkg/ringbuffer"
	"github.com/nvidia/nvsentinel/store-client/pkg/client"
	_ "github.com/nvidia/nvsentinel/store-client/pkg/datastore/providers"
	"github.com/nvidia/nvsentinel/store-client/pkg/factory"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/protobuf/proto"
)

type DatabaseStoreConnector struct {
	// databaseClient is the database-agnostic client
	databaseClient client.DatabaseClient
	// resourceSinkClients are client for pushing data to the resource count sink
	ringBuffer *ringbuffer.RingBuffer
	nodeName   string
}

func new(
	databaseClient client.DatabaseClient,
	ringBuffer *ringbuffer.RingBuffer,
	nodeName string,
) *DatabaseStoreConnector {
	return &DatabaseStoreConnector{
		databaseClient: databaseClient,
		ringBuffer:     ringBuffer,
		nodeName:       nodeName,
	}
}

func InitializeDatabaseStoreConnector(ctx context.Context, ringbuffer *ringbuffer.RingBuffer,
	clientCertMountPath string) (*DatabaseStoreConnector, error) {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODE_NAME is not set")
	}

	// Create database client factory using store-client
	clientFactory, err := createClientFactory(clientCertMountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client factory: %w", err)
	}

	// Create database client
	databaseClient, err := clientFactory.CreateDatabaseClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client: %w", err)
	}

	slog.Info("Successfully initialized database store connector")

	return new(databaseClient, ringbuffer, nodeName), nil
}

//nolint:cyclop
func InitializeMongoDbStoreConnector(ctx context.Context, ringbuffer *ringbuffer.RingBuffer,
	clientCertMountPath string) (*DatabaseStoreConnector, error) {
	mongoDbURI := os.Getenv("MONGODB_URI")
	if mongoDbURI == "" {
		return nil, fmt.Errorf("MONGODB_URI is not set")
	}

	mongoDbName := os.Getenv("MONGODB_DATABASE_NAME")
	if mongoDbName == "" {
		return nil, fmt.Errorf("MONGODB_DATABASE_NAME is not set")
	}

	mongoDbCollection := os.Getenv("MONGODB_COLLECTION_NAME")
	if mongoDbCollection == "" {
		return nil, fmt.Errorf("MONGODB_COLLECTION_NAME is not set")
	}

	// Check if TLS is enabled (default: true)
	tlsEnabledStr := os.Getenv("MONGODB_TLS_ENABLED")
	tlsEnabled := true // default to enabled
	if tlsEnabledStr == "false" {
		tlsEnabled = false
	}

	slog.Info("TLS configuration", 
		"os.Getenv_result", os.Getenv("MONGODB_TLS_ENABLED"), 
		"tlsEnabledStr", tlsEnabledStr, 
		"tlsEnabled", tlsEnabled)

	totalCACertTimeoutSeconds, err := getEnvAsInt("CA_CERT_MOUNT_TIMEOUT_TOTAL_SECONDS", 360)
	if err != nil {
		return nil, fmt.Errorf("invalid CA_CERT_MOUNT_TIMEOUT_TOTAL_SECONDS: %w", err)
	}

	intervalCACertSeconds, err := getEnvAsInt("CA_CERT_READ_INTERVAL_SECONDS", 5)
	if err != nil {
		return nil, fmt.Errorf("invalid CA_CERT_READ_INTERVAL_SECONDS: %w", err)
	}

	var clientOpts *options.ClientOptions

	if tlsEnabled {
		clientCertPath := clientCertMountPath + "/tls.crt"
		clientKeyPath := clientCertMountPath + "/tls.key"
		mongoCACertPath := clientCertMountPath + "/ca.crt"

		totalCertTimeout := time.Duration(totalCACertTimeoutSeconds) * time.Second
		intervalCert := time.Duration(intervalCACertSeconds) * time.Second

		// load CA certificate
		caCert, err := pollTillCACertIsMountedSuccessfully(mongoCACertPath, totalCertTimeout, intervalCert)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA certificate to pool")
		}

		// Load client certificate and key
		clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
		}

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
		}

		clientOpts = options.Client().ApplyURI(mongoDbURI).SetTLSConfig(tlsConfig)

		credential := options.Credential{
			AuthMechanism: "MONGODB-X509",
			AuthSource:    "$external",
		}
		clientOpts.SetAuth(credential)
	} else {
		// TLS disabled - use hardcoded username/password authentication
		clientOpts = options.Client().ApplyURI(mongoDbURI)
		
		credential := options.Credential{
			Username:   "root",
			Password:   "5FvYRx2jf1iLiZoQI76aHbwkFbPb05M3",
			AuthSource: "admin",
		}
		clientOpts.SetAuth(credential)
		slog.Info("MongoDB authentication configured with hardcoded credentials")
	}

	_, err = mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	totalTimeoutSeconds, err := getEnvAsInt("MONGODB_PING_TIMEOUT_TOTAL_SECONDS", 300)
	if err != nil {
		return nil, fmt.Errorf("invalid MONGODB_PING_TIMEOUT_TOTAL_SECONDS: %w", err)
	}

	intervalSeconds, err := getEnvAsInt("MONGODB_PING_INTERVAL_SECONDS", 5)
	if err != nil {
		return nil, fmt.Errorf("invalid MONGODB_PING_INTERVAL_SECONDS: %w", err)
	}

	totalTimeout := time.Duration(totalTimeoutSeconds) * time.Second
	interval := time.Duration(intervalSeconds) * time.Second

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return nil, fmt.Errorf("NODE_NAME is not set")
	}

	// For now, return a basic DatabaseStoreConnector
	// This function would need to be properly implemented to create a MongoDB-specific client
	// using the clientOpts, client, totalTimeout, and interval variables
	slog.Info("MongoDB TLS configuration initialized", 
		"tlsEnabled", tlsEnabled,
		"totalTimeout", totalTimeout,
		"interval", interval)

	// Create database client factory using store-client
	clientFactory, err := createClientFactory(clientCertMountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client factory: %w", err)
	}

	// Create database client
	databaseClient, err := clientFactory.CreateDatabaseClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create database client: %w", err)
	}

	slog.Info("Successfully initialized MongoDB store connector")

	return new(databaseClient, ringbuffer, nodeName), nil
}

func createClientFactory(databaseClientCertMountPath string) (*factory.ClientFactory, error) {
	if databaseClientCertMountPath != "" {
		return factory.NewClientFactoryFromEnvWithCertPath(databaseClientCertMountPath)
	}

	return factory.NewClientFactoryFromEnv()
}

func (r *DatabaseStoreConnector) FetchAndProcessHealthMetric(ctx context.Context) {
	// Build an in-memory cache of entity states from existing documents in the database
	for {
		select {
		case <-ctx.Done():
			slog.Info("Context canceled, exiting health metric processing loop")
			return
		default:
			healthEvents := r.ringBuffer.Dequeue()
			if healthEvents == nil || len(healthEvents.GetEvents()) == 0 {
				continue
			}

			err := r.insertHealthEvents(ctx, healthEvents)
			if err != nil {
				slog.Error("Error inserting health events", "error", err)
				r.ringBuffer.HealthMetricEleProcessingFailed(healthEvents)
			} else {
				r.ringBuffer.HealthMetricEleProcessingCompleted(healthEvents)
			}
		}
	}
}

// Disconnect closes the database client connection
// Safe to call multiple times - will not error if already disconnected
func (r *DatabaseStoreConnector) Disconnect(ctx context.Context) error {
	if r.databaseClient == nil {
		return nil
	}

	err := r.databaseClient.Close(ctx)
	if err != nil {
		// Log but don't return error if already disconnected
		// This can happen in tests where mtest framework also disconnects
		slog.Warn("Error disconnecting database client (may already be disconnected)", "error", err)

		return nil
	}

	slog.Info("Successfully disconnected database client")

	return nil
}

func (r *DatabaseStoreConnector) insertHealthEvents(
	ctx context.Context,
	healthEvents *protos.HealthEvents,
) error {
	// Prepare all documents for batch insertion
	healthEventWithStatusList := make([]interface{}, 0, len(healthEvents.GetEvents()))

	for _, healthEvent := range healthEvents.GetEvents() {
		// CRITICAL FIX: Clone the HealthEvent to avoid pointer reuse issues with gRPC buffers
		// Without this clone, the healthEvent pointer may point to reused gRPC buffer memory
		// that gets overwritten by subsequent requests, causing data corruption in MongoDB.
		// This manifests as events having wrong isfatal/ishealthy/message values.
		clonedHealthEvent := proto.Clone(healthEvent).(*protos.HealthEvent)

		healthEventWithStatusObj := model.HealthEventWithStatus{
			CreatedAt:   time.Now().UTC(),
			HealthEvent: clonedHealthEvent,
		}
		healthEventWithStatusList = append(healthEventWithStatusList, healthEventWithStatusObj)
	}

	// Insert all documents in a single batch operation
	// This ensures MongoDB generates INSERT operations (not UPDATE) for change streams
	// Note: InsertMany is already atomic - either all documents are inserted or none are
	_, err := r.databaseClient.InsertMany(ctx, healthEventWithStatusList)
	if err != nil {
		return fmt.Errorf("insertMany failed: %w", err)
	}

	return nil
}

func GenerateRandomObjectID() string {
	return uuid.New().String()
}

// Helper function to get environment variable as int with default value
func getEnvAsInt(key string, defaultValue int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue, nil
	}
	return strconv.Atoi(value)
}

// Helper function to poll for CA certificate until it's available
func pollTillCACertIsMountedSuccessfully(caCertPath string, totalTimeout, interval time.Duration) ([]byte, error) {
	start := time.Now()
	for {
		caCert, err := os.ReadFile(caCertPath)
		if err == nil {
			return caCert, nil
		}
		
		if time.Since(start) > totalTimeout {
			return nil, fmt.Errorf("timeout waiting for CA certificate at %s: %w", caCertPath, err)
		}
		
		time.Sleep(interval)
	}
}
