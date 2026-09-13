package engineclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/zcayou/k8s-authz/internal/condition"
	"github.com/zcayou/k8s-authz/internal/engine"
	"github.com/zcayou/k8s-authz/internal/model"
)

// Target is one engine pod: its address, and the server name and roots its
// serving certificate is verified with.
type Target struct {
	Address    string
	ServerName string
	Roots      *x509.CertPool
}

const (
	timeout           = 10 * time.Second
	maxResponseBytes  = 65536
	maxInstalledBytes = 1024
)

// Client manages engines through their management API over mTLS.
type Client struct {
	certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// New returns a client that presents the certificate certificate returns,
// so a renewed certificate is used from the next handshake.
func New(certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *Client {
	return &Client{certificate: certificate}
}

// Installed is what an engine serves: its state's revision and its conditions
// module's digest, each empty when absent.
type Installed struct {
	Revision         model.RevisionID `json:"revision"`
	ConditionsDigest string           `json:"conditions_digest"`
}

// Installed returns what target serves.
func (c *Client) Installed(ctx context.Context, target Target) (Installed, error) {
	result, err := c.get(ctx, target, "/v1/data/authz/evaluator/installed", maxInstalledBytes)
	if err != nil || result == nil {
		return Installed{}, err
	}
	var installed Installed
	if err = json.Unmarshal(result, &installed); err != nil {
		return Installed{}, fmt.Errorf("decode installed state: %w", err)
	}
	return installed, nil
}

// PutConditions installs module as target's conditions module, replacing
// the one it holds. The engine compiles the module with the others it holds
// before it responds.
func (c *Client) PutConditions(ctx context.Context, target Target, module condition.Module) error {
	_, err := c.request(ctx, target, http.MethodPut, "/v1/policies/"+condition.PolicyID, module.Source, maxResponseBytes)
	return err
}

// Replace installs state, the encoded state document, on target. The engine
// commits the write before it responds.
func (c *Client) Replace(ctx context.Context, target Target, state []byte) error {
	_, err := c.request(ctx, target, http.MethodPut, "/v1/data/authz/state", state, maxResponseBytes)
	return err
}

// Snapshot returns the state document target serves, as the engine encodes
// it, or nil when it has none.
func (c *Client) Snapshot(ctx context.Context, target Target) (json.RawMessage, error) {
	return c.get(ctx, target, "/v1/data/authz/state", engine.MaxExportBytes)
}

// get returns the document at path of target's data API, or nil when
// the document is undefined.
func (c *Client) get(ctx context.Context, target Target, path string, limit int64) (json.RawMessage, error) {
	data, err := c.request(ctx, target, http.MethodGet, path, nil, limit)
	if err != nil {
		return nil, err
	}
	var response struct {
		Result json.RawMessage `json:"result"`
	}
	if err = json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("decode management response: %w", err)
	}
	return response.Result, nil
}

func (c *Client) request(ctx context.Context, target Target, method, path string, body []byte, limit int64) ([]byte, error) {
	// Each request dials its pod afresh. A pod IP can be reused by another
	// service's engine, so connections are never pooled across the identities
	// they were verified for.
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, RootCAs: target.Roots, ServerName: target.ServerName,
			GetClientCertificate: c.certificate,
		},
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, "https://"+target.Address+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build management request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err = errors.Join(err, response.Body.Close()); err != nil {
		return nil, fmt.Errorf("read management response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("management response to %s %s exceeds %d bytes", method, path, limit)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("management request %s %s returned HTTP %d", method, path, response.StatusCode)
	}
	return data, nil
}
