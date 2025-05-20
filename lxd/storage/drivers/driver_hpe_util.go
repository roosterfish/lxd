package drivers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/canonical/lxd/lxd/storage/block"
	"github.com/canonical/lxd/lxd/storage/connectors"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/logger"
	"github.com/canonical/lxd/shared/revert"
)

// hpeAPIVersion is the HPE Storage API version used by LXD.

const hpeAPIVersion = "1.14.2"

// hpeServiceNameMapping maps HPE Storage mode in LXD to the corresponding HPE Storage
// service name.
var hpeServiceNameMapping = map[string]string{
	connectors.TypeISCSI: "iscsi",
	connectors.TypeNVME:  "nvme-tcp",
}

// hpeVolTypePrefixes maps volume type to storage volume name prefix.
// Use smallest possible prefixes since HPE Storage volume names are limited to 63 characters.
var hpeVolTypePrefixes = map[VolumeType]string{
	VolumeTypeContainer: "c",
	VolumeTypeVM:        "v",
	VolumeTypeImage:     "i",
	VolumeTypeCustom:    "u",
}

// hpeContentTypeSuffixes maps volume's content type to storage volume name suffix.
var hpeContentTypeSuffixes = map[ContentType]string{
	// Suffix used for block content type volumes.
	ContentTypeBlock: "b",

	// Suffix used for ISO content type volumes.
	ContentTypeISO: "i",
}

// hpeSnapshotPrefix is a prefix used for HPE Storage snapshots to avoid name conflicts
// when creating temporary volume from the snapshot.
var hpeSnapshotPrefix = "s"

// hpeError represents an error response from the HPE Storage API.
type hpeError struct {
	Code       int    `json:"code"`
	Desc       string `json:"desc"`
	statusCode int    // Used to store the HTTP status code.
}

// Error implements the error interface for hpeError.
func (p *hpeError) Error() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("HTTP Error Code: %d. HPE Error Code: %d. HPE Description: %s", p.statusCode, p.Code, p.Desc)
}

// isHpeErrorOf checks if the error is of type hpeError and matches the status code.
func isHpeErrorOf(err error, statusCode int, substrings ...string) bool {
	perr, ok := err.(*hpeError)
	if !ok {
		return false
	}

	if perr.Code != statusCode {
		return false
	}

	if len(substrings) == 0 {
		return true
	}

	errMsg := strings.ToLower(perr.Desc)
	for _, substring := range substrings {
		if strings.Contains(errMsg, strings.ToLower(substring)) {
			return true
		}
	}

	return false
}

// hpeIsNotFoundError returns true if the error is of type hpeError, its status code is 400 (bad request),
// and the error message contains a substring indicating the resource was not found.
func isHpeErrorNotFound(err error) bool {
	return isHpeErrorOf(err, http.StatusNotFound, "Not found", "Does not exist", "No such volume or snapshot")
}

// hpeResponse wraps the response from the HPE Storage API. In most cases, the response
// contains a list of items, even if only one item is returned.
type hpeResponse[T any] struct {
	Items []T `json:"items"`
}

// hpePort represents a network interface in HPE Storage.
type hpeNetworkInterface struct {
	Name     string `json:"name"`
	Ethernet struct {
		Address string `json:"address,omitempty"`
	} `json:"eth,omitempty"`
}

// hpeEntity represents a generic entity in HPE Storage.
type hpeEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// hpeSpace represents the usage data of HPE Storage resource.
type hpeSpace struct {
	// Total reserved space.
	// For volumes, this is the available space or quota.
	// For storage pools, this is the total reserved space (not the quota).
	TotalBytes int64 `json:"total_provisioned"`

	// Amount of logically written data that a volume or a snapshot references.
	// This value is compared against the quota, therefore, it should be used for
	// showing the actual used space. Although, the actual used space is most likely
	// less than this value due to the data reduction that is done by HPE Storage.
	UsedBytes int64 `json:"virtual"`
}

// hpeStorageArray represents a storage array in HPE Storage.
type hpeStorageArray struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Capacity int64    `json:"capacity"`
	Space    hpeSpace `json:"space"`
}

// hpeProtectionGroup represents a protection group in HPE Storage.
type hpeProtectionGroup struct {
	Name        string `json:"name"`
	IsDestroyed bool   `json:"destroyed"`
}

// hpeDefaultProtection represents a default protection in HPE Storage.
type hpeDefaultProtection struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type hpeStoragePool struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// hpeVolume represents a volume in HPE Storage.
type hpeVolume struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Serial      string   `json:"serial"`
	IsDestroyed bool     `json:"destroyed"`
	Space       hpeSpace `json:"space"`
}

// hpePortPos represents the port position in HPE Storage.
type hpePortPos struct {
	Node     int `json:"node"`
	Slot     int `json:"slot"`
	CardPort int `json:"cardPort"`
}

// hpeFCPath represents a Fibre Channel Path in HPE Storage.
type hpeFCPath struct {
	WWN     string     `json:"wwn"`
	PortPos hpePortPos `json:"portPos"`
}

// hpeISCSIPath represents an iSCSI Path in HPE Storage.
type hpeISCSIPath struct {
	Name      string `json:"name"`
	IPAddr    string `json:"IPAddr"`
	HostSpeed int    `json:"hostSpeed"`
}

// hpeNVMETCPPath represents a NVMe TCP Path in HPE Storage.
type hpeNVMETCPPath struct {
	IP      string     `json:"IP"`
	PortPos hpePortPos `json:"portPos"`
	NQN     string     `json:"nqn"`
}

// hpeHost represents a host in HPE Storage.
type hpeHost struct {
	ID           int              `json:"id"`
	Name         string           `json:"name"`
	FCPaths      []hpeFCPath      `json:"FCPaths"`
	iSCSIPaths   []hpeISCSIPath   `json:"iSCSIPaths"`
	NVMETCPPaths []hpeNVMETCPPath `json:"NVMETCPPaths"`
}

type hpeVLUN struct {
	LUN      int    `json:"lun"`
	Hostname string `json:"hostname"`
	Serial   string `json:"serial"`
}

type hpeRespMembers[T any] struct {
	Total   int `json:"total"`
	Members []T `json:"members"`
}

// hpePort represents a port in HPE Storage.
type hpePort struct {
	Protocol  int    `json:"protocol"`
	NodeWWN   string `json:"nodeWWN"`
	LinkState int    `json:"linkState"`
}

// hpeClient holds the HPE Storage HTTP client and an access token.
type hpeClient struct {
	driver     *hpe
	sessionKey string
}

// newHpeClient creates a new instance of the HTTP HPE Storage client.
func newHpeClient(driver *hpe) *hpeClient {
	return &hpeClient{
		driver: driver,
	}
}

// createBodyReader creates a reader for the given request body contents.
func (p *hpeClient) createBodyReader(contents map[string]any) (io.Reader, error) {
	body := &bytes.Buffer{}

	err := json.NewEncoder(body).Encode(contents)
	if err != nil {
		return nil, fmt.Errorf("Failed to write request body: %w", err)
	}

	return body, nil
}

// request issues a HTTP request against HPE Storage WSAPI
func (p *hpeClient) request(method string, url url.URL, reqBody map[string]any, reqHeaders map[string]string, respBody any, respHeaders map[string]string) error {
	logger.Debug("HPE request()")
	// Extract scheme and host from the gateway URL.
	scheme, host, found := strings.Cut(p.driver.config["hpe.wsapi.url"], "://")
	if !found {
		return fmt.Errorf("Invalid HPE Storage WSAPI URL: %q", p.driver.config["hpe.wsapi.url"])
	}

	// Set request URL scheme and host.
	url.Scheme = scheme
	url.Host = host

	var err error
	var reqBodyReader io.Reader

	if reqBody != nil {
		reqBodyReader, err = p.createBodyReader(reqBody)
		if err != nil {
			return err
		}
	}

	req, err := http.NewRequest(method, url.String(), reqBodyReader)
	if err != nil {
		return fmt.Errorf("Failed to create request: %w", err)
	}

	// Set custom request headers.
	for k, v := range reqHeaders {
		req.Header.Add(k, v)
	}

	req.Header.Add("Accept", "application/json")
	if reqBody != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: shared.IsFalse(p.driver.config["hpe.wsapi.verifyssl"]),
			},
		},
	}

	logger.Debugf("Request URL: %s", url.String())
	logger.Debugf("Request Method: %s", req.Method)

	parsedReqHeaders := ""
	for name, values := range req.Header {
		parsedReqHeaders += fmt.Sprintf("%s: %s\n", name, strings.Join(values, ", "))
	}
	logger.Debugf("Request Headers:\n%s", parsedReqHeaders)

	// logger.Debugf("Request Body:\n%s", reqBody)

	// reqBodyDisplay := make([]string, 0, len(reqBody))
	// for k, v := range reqBody {
	// 	reqBodyDisplay = append(reqBodyDisplay, fmt.Sprintf("%s=%v", k, v))
	// }
	// logger.Debugf("Request Body (KV):\n%s", strings.Join(reqBodyDisplay, "\n"))

	reqBodyJSON, err := json.MarshalIndent(reqBody, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}
	logger.Debugf("Request Body (JSON):\n%s", string(reqBodyJSON))

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %w", err)
	}

	logger.Debugf("Response HTTP Status Code: %d", resp.StatusCode)

	defer resp.Body.Close()

	var responseBodyBuffer bytes.Buffer
	teeReader := io.TeeReader(resp.Body, &responseBodyBuffer)
	bodyBytes, err := io.ReadAll(teeReader)
	if err != nil {
		return fmt.Errorf("Failed to read response body for TeeReader: %w", err)
	}

	allowedCT := "application/json"
	if resp.Header.Get("Content-Type") != allowedCT &&
		len(bodyBytes) > 0 {
		return fmt.Errorf("Response Header Content-type: %q. Only %q responses allowed for non-empty Response Body", resp.Header.Get("Content-Type"), allowedCT)
	}

	parsedRespHeaders := ""
	undesiredRespHeaders := []string{
		"X-Frame-Options",
		"Set-Cookie",
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"Cache-Control",
		"Vary",
		"X-Content-Type-Options",
		"Content-Language",
		"X-Xss-Protection",
		"Pragma",
		"Accept-Ranges",
		"Last-Modified",
	}

	for name, values := range resp.Header {
		skip := slices.Contains(undesiredRespHeaders, name)
		if skip {
			continue
		}
		parsedRespHeaders += fmt.Sprintf("%s: %s\n", name, strings.Join(values, ", "))
	}
	logger.Debugf("Response Headers (filtered):\n%s", parsedRespHeaders)

	var prettyBody any
	if json.Unmarshal(bodyBytes, &prettyBody) == nil {
		b, _ := json.MarshalIndent(prettyBody, "", "  ")
		logger.Debugf("Response Body size: %d", len(b))
		if len(b) > 100 {
			logger.Debugf("Response Body (JSON) - Turned off due to output size limit")
		} else {
			logger.Debugf("Response Body (JSON):\n%s", string(b))
		}
	} else {
		logger.Debugf("Response Body (RAW):\n%s", string(bodyBytes))
	}

	// The unauthorized error is reported when an invalid (or expired) access token is provided.
	// Wrap unauthorized requests into an API status error to allow easier checking for expired
	// token in the requestAuthenticated function.
	// if resp.StatusCode == http.StatusUnauthorized {
	// 	return api.StatusErrorf(http.StatusUnauthorized, "xxx 1 Unauthorized request")
	// } else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
	// 	return api.StatusErrorf(http.StatusForbidden, "xxx 2 Unauthorized status code: %d", resp.StatusCode)
	// }

	// Overwrite the response data type if an error is detected.
	// if resp.StatusCode != http.StatusOK &&
	// 	resp.StatusCode != http.StatusCreated &&
	// 	resp.StatusCode != http.StatusAccepted {
	// 	respBody = &hpeError{}
	// }

	if resp.StatusCode >= 400 {
		respBody = &hpeError{}
		err := json.Unmarshal(bodyBytes, respBody)
		if err != nil {
			return fmt.Errorf("HPE failed to parse WSAPI error response: %w", err)
		}
	}

	// Extract the response body if requested.
	if len(bodyBytes) > 0 {
		err = json.Unmarshal(bodyBytes, &respBody)
		if err != nil {
			return fmt.Errorf("HPE failed to read response body from %q: %w", url.String(), err)
		}
	}

	// Extract the response headers if requested.
	if respHeaders != nil {
		for k, v := range resp.Header {
			respHeaders[k] = strings.Join(v, ",")
		}
	}

	// Return the formatted error from the body
	hpeErr, assert := respBody.(*hpeError)
	if assert {
		hpeErr.statusCode = resp.StatusCode
		return hpeErr
	}

	return nil
}

// requestAuthenticated issues an authenticated HTTP request against the HPE Storage gateway.
// In case the Session Key is expired, the function will try to obtain a new one.
func (p *hpeClient) requestAuthenticated(method string, url url.URL, reqBody map[string]any, respBody any) error {
	logger.Debug("HPE requestAuthenticated()")

	// If request fails with an unauthorized error, the request will be retried after
	// requesting a new Session Key.
	// retries := 0

	// for {
	// 	if retries >= 1 {
	// 		return fmt.Errorf("HPE maximium retires reached: %d. URL: %q. Method: %s", retries, url.String(), method)
	// 	}

	// retries++
	// logger.Debugf("HPE atempt: %d", retries)

	// Ensure we are logged into the HPE Storage.
	err := p.login()
	if err != nil {
		return err
	}

	// Add Session Key to Headers.
	reqHeaders := map[string]string{
		"X-HP3PAR-WSAPI-SessionKey": p.sessionKey,
	}
	logger.Debugf("HPE add Session Key to Headers: %s", p.sessionKey)

	// Initiate request.
	err = p.request(method, url, reqBody, reqHeaders, respBody, nil)

	if err != nil {
		// if api.StatusErrorCheck(err, http.StatusForbidden) {
		// logger.Debugf("HPE resetting Session Key: %s", err)
		// 	p.sessionKey = ""
		// } else {
		// 	logger.Debugf("HPE authorized request failed for %s %q with error: %s", strings.ToUpper(method), url.String(), err)
		// }
		// // continue
		// }

		// return nil

		hpeErr, assert := respBody.(*hpeError)
		if assert {
			logger.Debugf("HPE DEBUG %d", hpeErr.statusCode)
			logger.Debugf("HPE DEBUG %d", hpeErr.Code)
			logger.Debugf("HPE DEBUG %s", hpeErr.Desc)
		} else {
			// logger.Debugf("HPE DEBUG requestAuthenticated() hpeError from Body: %s", respBody)
			logger.Debugf("HPE DEBUG requestAuthenticated() hpeError assert: %s", hpeErr)
			// return nil
		}

		logger.Debugf("HPE authorized request failed for %s %q with error: %s", strings.ToUpper(method), url.String(), err)
		return err
	}

	return nil
}

// getAPIVersion returns the list of API versions that are supported by the HPE Storage.
func (p *hpeClient) getAPIVersions() ([]string, error) {
	var resp struct {
		APIVersions []string `json:"version"`
	}

	url := api.NewURL().Path("api", "v1", "wsapiconfiguration")
	err := p.request(http.MethodGet, url.URL, nil, nil, &resp, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve available API versions from HPE Storage: %w", err)
	}

	if len(resp.APIVersions) == 0 {
		return nil, fmt.Errorf("HPE Storage does not support any API versions")
	}

	return resp.APIVersions, nil
}

// login initiates request() using WSAPI username and password.
// If successful then Session Key is retrieved and stored within hpeClient client.
// Once stored the Session Key is reused for further requests.
func (p *hpeClient) login() error {
	logger.Debug("HPE login()")

	if p.sessionKey != "" {
		logger.Debugf("HPE reusing stored Session Key: %s", p.sessionKey)
		return nil
	}

	var respBody struct {
		Key  string `json:"key"`
		Desc string `json:"desc"`
	}

	body := map[string]any{
		"user":        p.driver.config["hpe.wsapi.username"],
		"password":    p.driver.config["hpe.wsapi.password"],
		"sessionType": 1,
	}

	url := api.NewURL().Path("api", "v1", "credentials")
	respHeaders := make(map[string]string)

	err := p.request(http.MethodPost, url.URL, body, nil, &respBody, respHeaders)
	if err != nil {
		return fmt.Errorf("HPE failed to send login request: %w", err)
	}

	if respBody.Key != "" {
		p.sessionKey = respBody.Key
		logger.Debugf("HPE saved Session Key: %s", p.sessionKey)
		return nil
	}

	return errors.New("HPE received an empty Session Key")
}

// getNetworkInterfaces retrieves a valid HPE Storage network interfaces, which
// means the interface has an IP address configured and is enabled. The result
// can be filtered by a specific service name, where an empty string represents
// no filtering.
func (p *hpeClient) getNetworkInterfaces(service string) ([]hpeNetworkInterface, error) {
	logger.Debug("HPE getNetworkInterfaces()")

	var resp hpeResponse[hpeNetworkInterface]

	// Retrieve enabled network interfaces that have an IP address configured.
	url := api.NewURL().Path("network-interfaces").WithQuery("filter", "enabled='true'").WithQuery("filter", "eth.address")
	if service != "" {
		url = url.WithQuery("filter", "services='"+service+"'")
	}

	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Failed to retrieve HPE Storage network interfaces: %w", err)
	}

	return resp.Items, nil
}

// getStoragePool returns the storage pool with the given name.
func (p *hpeClient) getStoragePool(poolName string) (*hpeStoragePool, error) {
	logger.Debugf("HPE getStoragePool()")

	var resp struct {
		Total   int              `json:"total"`
		Members []hpeStoragePool `json:"members"`
	}

	url := api.NewURL().Path("api", "v1", "cpgs")
	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Failed to get storage pool %q: %w", poolName, err)
	}

	var foundMember *hpeStoragePool
	for _, member := range resp.Members {
		if member.Name == poolName {
			foundMember = &member
			break
		}
	}

	if foundMember == nil {
		logger.Debugf("HPE storage pool %q not found", poolName)
		return nil, fmt.Errorf("HPE Storage pool %q not found", poolName)
	} else {
		logger.Debugf("HPE found storage pool: %s. ID: %d. UUID: %s", foundMember.Name, foundMember.ID, foundMember.UUID)
	}

	return foundMember, nil
}

// createStoragePool creates a storage pool.
func (p *hpeClient) createStoragePool(poolName string, size int64) error {
	logger.Debugf("HPE createStoragePool()")

	revert := revert.New()
	defer revert.Fail()

	req := map[string]any{
		"name": poolName,
	}

	logger.Debugf("HPE check if %s is already created", poolName)
	_, err := p.getStoragePool(poolName)
	if err == nil {
		logger.Debugf("HPE storage pool %s already created", poolName)
	} else {
		logger.Debugf("HPE creating a new storage pool: %s", poolName)
		url := api.NewURL().Path("api", "v1", "cpgs")
		err = p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
		if err != nil {
			return fmt.Errorf("Failed to create storage pool %q: %w", poolName, err)
		}
	}

	revert.Add(func() { _ = p.deleteStoragePool(poolName) })

	revert.Success()
	return nil
}

// updateStoragePool updates an existing storage pool (HPE Storage pod).
func (p *hpeClient) updateStoragePool(poolName string, size int64) error {
	logger.Debugf("HPE updateStoragePool()")
	req := make(map[string]any)
	if size > 0 {
		req["quota_limit"] = size
	}

	url := api.NewURL().Path("pods").WithQuery("names", poolName)
	err := p.requestAuthenticated(http.MethodPatch, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf("Failed to update storage pool %q: %w", poolName, err)
	}

	return nil
}

// deleteStoragePool deletes a storage pool.
func (p *hpeClient) deleteStoragePool(poolName string) error {
	logger.Debugf("HPE deleteStoragePool()")

	_, err := p.getStoragePool(poolName)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}

		return nil
	}

	url := api.NewURL().Path("api", "v1", "cpgs", poolName)
	err = p.requestAuthenticated(http.MethodDelete, url.URL, nil, nil)
	if err != nil {
		if isHpeErrorNotFound(err) {
			return nil
		}

		return fmt.Errorf("Failed to delete storage pool %q: %w", poolName, err)
	}

	return nil
}

// getVolume returns the volume behind volumeID.
func (p *hpeClient) getVolume(poolName string, volName string) (*hpeVolume, error) {
	logger.Debugf("HPE getVolume()")

	var resp hpeResponse[hpeVolume]

	url := api.NewURL().Path("api", "v1", "volumes", volName)
	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		// logger.Debugf("HPE DEBUG getVolume() Error: %s", err)
		// if isHpeErrorNotFound(err) {
		// 	return nil, api.StatusErrorf(http.StatusNotFound, "Volume %q not found", volName)
		// }

		// return nil, fmt.Errorf("Failed to get volume %q: %w", volName, err)
		logger.Debugf("HPE volume not found: %s", volName)

		return nil, nil
	}

	if len(resp.Items) == 0 {
		return nil, api.StatusErrorf(http.StatusNotFound, "Volume %q not found", volName)
	}

	return &resp.Items[0], nil
}

// createVolume creates a new volume in the given storage pool. The volume is created with
// supplied size in bytes. Upon successful creation, volume's ID is returned.
func (p *hpeClient) createVolume(poolName string, volName string, sizeBytes int64) error {
	logger.Debugf("HPE createVolume()")

	req := map[string]any{
		"name":    volName,
		"cpg":     poolName,
		"sizeMiB": sizeBytes / 1024 / 1024,
		"tpvv":    true,
	}

	// Prevent default protection groups to be applied on the new volume, which can
	// prevent us from eradicating the volume once deleted.
	url := api.NewURL().Path("api", "v1", "volumes")
	err := p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf("Failed to create volume %q in storage pool %q: %w", volName, poolName, err)
	}

	return nil
}

// getVLUN returns VLUN related data of given volumeName
func (p *hpeClient) getVLUN(volumeName string) (*hpeVLUN, error) {
	var resp hpeRespMembers[hpeVLUN]

	url := api.NewURL().Path("api", "v1", "vluns").WithQuery("query", "\"volumeName"+"=="+volumeName+"\"")

	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Fail to get LUN related data for volume %s | %w", volumeName, err)
	}

	if len(resp.Members) == 0 {
		return nil, fmt.Errorf("No VLUN found for volume: %s", volumeName)
	}

	member := resp.Members[0]
	logger.Debugf("VLUN: %d | Hostname: %s | Serial: %s", member.LUN, member.Hostname, member.Serial)
	return &member, nil
}

// deleteVolume deletes an exisiting volume in the given storage pool.
func (p *hpeClient) deleteVolume(poolName string, volName string) error {
	url := api.NewURL().Path("api", "v1", "volumes", volName)

	// // To destroy the volume, we need to patch it by setting the destroyed to true.
	// err := p.requestAuthenticated(http.MethodPatch, url.URL, nil, nil)
	// if err != nil {
	// 	return fmt.Errorf("Failed to destroy volume %q in storage pool %q: %w", volName, poolName, err)
	// }

	// Afterwards, we can eradicate the volume. If this operation fails, the volume will remain
	// in the destroyed state.
	err := p.requestAuthenticated(http.MethodDelete, url.URL, nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete volume %q in storage pool %q: %w", volName, poolName, err)
	}

	return nil
}

// resizeVolume resizes an existing volume. This function does not resize any filesystem inside the volume.
func (p *hpeClient) resizeVolume(poolName string, volName string, sizeBytes int64, truncate bool) error {
	req := map[string]any{
		"provisioned": sizeBytes,
	}

	url := api.NewURL().Path("volumes").WithQuery("names", poolName+"::"+volName).WithQuery("truncate", fmt.Sprint(truncate))
	err := p.requestAuthenticated(http.MethodPatch, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf("Failed to resize volume %q in storage pool %q: %w", volName, poolName, err)
	}

	return nil
}

// copyVolume copies a source volume into destination volume. If overwrite is set to true,
// the destination volume will be overwritten if it already exists.
func (p *hpeClient) copyVolume(srcPoolName string, srcVolName string, dstPoolName string, dstVolName string, overwrite bool) error {
	req := map[string]any{
		"source": map[string]string{
			"name": srcPoolName + "::" + srcVolName,
		},
	}

	url := api.NewURL().Path("volumes").WithQuery("names", dstPoolName+"::"+dstVolName).WithQuery("overwrite", fmt.Sprint(overwrite))

	if !overwrite {
		// Disable default protection groups when creating a new volume to avoid potential issues
		// when deleting the volume because protection group may prevent volume eridication.
		url = url.WithQuery("with_default_protection", "false")
	}

	err := p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf(`Failed to copy volume "%s/%s" to "%s/%s": %w`, srcPoolName, srcVolName, dstPoolName, dstVolName, err)
	}

	return nil
}

// getVolumeSnapshots retrieves all existing snapshot for the given storage volume.
func (p *hpeClient) getVolumeSnapshots(poolName string, volName string) ([]hpeVolume, error) {
	var resp hpeResponse[hpeVolume]

	url := api.NewURL().Path("volume-snapshots").WithQuery("source_names", poolName+"::"+volName)
	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		if isHpeErrorNotFound(err) {
			return nil, api.StatusErrorf(http.StatusNotFound, "Volume %q not found", volName)
		}

		return nil, fmt.Errorf("Failed to retrieve snapshots for volume %q in storage pool %q: %w", volName, poolName, err)
	}

	return resp.Items, nil
}

// getVolumeSnapshot retrieves an existing snapshot for the given storage volume.
func (p *hpeClient) getVolumeSnapshot(poolName string, volName string, snapshotName string) (*hpeVolume, error) {
	var resp hpeResponse[hpeVolume]

	url := api.NewURL().Path("volume-snapshots").WithQuery("names", poolName+"::"+volName+"."+snapshotName)
	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		if isHpeErrorNotFound(err) {
			return nil, api.StatusErrorf(http.StatusNotFound, "Snapshot %q not found", snapshotName)
		}

		return nil, fmt.Errorf("Failed to retrieve snapshot %q for volume %q in storage pool %q: %w", snapshotName, volName, poolName, err)
	}

	if len(resp.Items) == 0 {
		return nil, api.StatusErrorf(http.StatusNotFound, "Snapshot %q not found", snapshotName)
	}

	return &resp.Items[0], nil
}

// createVolumeSnapshot creates a new snapshot for the given storage volume.
func (p *hpeClient) createVolumeSnapshot(poolName string, volName string, snapshotName string) error {
	req := map[string]any{
		"suffix": snapshotName,
	}

	url := api.NewURL().Path("volume-snapshots").WithQuery("source_names", poolName+"::"+volName)
	err := p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf("Failed to create snapshot %q for volume %q in storage pool %q: %w", snapshotName, volName, poolName, err)
	}

	return nil
}

// deleteVolumeSnapshot deletes an existing snapshot for the given storage volume.
func (p *hpeClient) deleteVolumeSnapshot(poolName string, volName string, snapshotName string) error {
	snapshot, err := p.getVolumeSnapshot(poolName, volName, snapshotName)
	if err != nil {
		return err
	}

	if !snapshot.IsDestroyed {
		// First destroy the snapshot.
		req := map[string]any{
			"destroyed": true,
		}

		// Destroy snapshot.
		url := api.NewURL().Path("volume-snapshots").WithQuery("names", poolName+"::"+volName+"."+snapshotName)
		err = p.requestAuthenticated(http.MethodPatch, url.URL, req, nil)
		if err != nil {
			return fmt.Errorf("Failed to destroy snapshot %q for volume %q in storage pool %q: %w", snapshotName, volName, poolName, err)
		}
	}

	// Delete (eradicate) snapshot.
	url := api.NewURL().Path("volume-snapshots").WithQuery("names", poolName+"::"+volName+"."+snapshotName)
	err = p.requestAuthenticated(http.MethodDelete, url.URL, nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete snapshot %q for volume %q in storage pool %q: %w", snapshotName, volName, poolName, err)
	}

	return nil
}

// restoreVolumeSnapshot restores the volume by copying the volume snapshot into its parent volume.
func (p *hpeClient) restoreVolumeSnapshot(poolName string, volName string, snapshotName string) error {
	return p.copyVolume(poolName, volName+"."+snapshotName, poolName, volName, true)
}

// copyVolumeSnapshot copies the volume snapshot into destination volume. Destination volume is overwritten
// if already exists.
func (p *hpeClient) copyVolumeSnapshot(srcPoolName string, srcVolName string, srcSnapshotName string, dstPoolName string, dstVolName string) error {
	return p.copyVolume(srcPoolName, srcVolName+"."+srcSnapshotName, dstPoolName, dstVolName, true)
}

// getHosts retrieves an existing HPE Storage host.
func (p *hpeClient) getHosts() ([]hpeHost, error) {
	logger.Debugf("HPE getHosts()")

	var resp hpeRespMembers[hpeHost]

	url := api.NewURL().Path("api", "v1", "hosts")
	err := p.requestAuthenticated(http.MethodGet, url.URL, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Failed to get hosts: %w", err)
	}

	logger.Debugf("HPE total hosts found: %d", len(resp.Members))
	return resp.Members, nil
}

// getCurrentHost retrieves the HPE Storage host linked to the current LXD host.
// The HPE Storage host is considered a match if it includes the fully qualified
// name of the LXD host that is determined by the configured mode.
func (p *hpeClient) getCurrentHost() (*hpeHost, error) {
	logger.Debugf("HPE getCurrentHost()")

	connector, err := p.driver.connector()
	if err != nil {
		return nil, err
	}

	qn, err := connector.QualifiedName()
	if err != nil {
		return nil, err
	}
	logger.Debugf("HPE searching for: %s", qn)

	hosts, err := p.getHosts()
	if err != nil {
		return nil, err
	}

	mode := connector.Type()

	for _, host := range hosts {
		if mode == connectors.TypeISCSI {
			for _, iscsiPath := range host.iSCSIPaths {
				if iscsiPath.Name == qn {
					logger.Debugf("HPE iSCSI QN found: %s", qn)
					return &host, nil
				}
			}
		}

		if mode == connectors.TypeNVME {
			for _, nvmePath := range host.NVMETCPPaths {
				if nvmePath.NQN == qn {
					logger.Debugf("HPE NVMe/TCP QN found: %s", qn)
					return &host, nil
				}
			}
		}
	}

	logger.Debugf("HPE getCurrentHost() host NOT found: %s", qn)

	return nil, api.StatusErrorf(http.StatusNotFound, "Host with qualified name %q not found", qn)
}

// createHost creates a new host with provided initiator qualified names that can be associated
// with specific volumes.
func (p *hpeClient) createHost(hostName string, qns string) error {
	logger.Debugf("HPE createHost()")

	req := make(map[string]any)

	connector, err := p.driver.connector()
	if err != nil {
		return err
	}
	req["name"] = hostName

	switch connector.Type() {
	case connectors.TypeISCSI:
		req["iqns"] = qns
	case connectors.TypeNVME:
		req["NQN"] = qns
		req["transportType"] = 2
	default:
		return fmt.Errorf("Unsupported HPE Storage mode %q", connector.Type())
	}

	url := api.NewURL().Path("api", "v1", "hosts")
	err = p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
	if err != nil {
		if isHpeErrorOf(err, http.StatusBadRequest, "Host already exists.") {
			return api.StatusErrorf(http.StatusConflict, "Host %q already exists", hostName)
		}

		return fmt.Errorf("Failed to create host %q: %w", hostName, err)
	}

	return nil
}

// updateHost updates an existing host.
func (p *hpeClient) updateHost(hostName string, qns string) error {
	logger.Debugf("HPE updateHost()")

	req := make(map[string]any, 1)

	connector, err := p.driver.connector()
	if err != nil {
		return err
	}

	switch connector.Type() {
	case connectors.TypeISCSI:
		req["iqns"] = qns
	case connectors.TypeNVME:
		req["nqns"] = qns
	default:
		return fmt.Errorf("Unsupported HPE Storage mode %q", connector.Type())
	}

	// To destroy the volume, we need to patch it by setting the destroyed to true.
	url := api.NewURL().Path("hosts").WithQuery("names", hostName)
	err = p.requestAuthenticated(http.MethodPatch, url.URL, req, nil)
	if err != nil {
		return fmt.Errorf("Failed to update host %q: %w", hostName, err)
	}

	return nil
}

// deleteHost deletes an existing host.
func (p *hpeClient) deleteHost(hostName string) error {
	logger.Debugf("HPE deleteHost()")

	url := api.NewURL().Path("api", "v1", "hosts", hostName)
	err := p.requestAuthenticated(http.MethodDelete, url.URL, nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete host %q: %w", hostName, err)
	}

	return nil
}

// connectHostToVolume creates a connection between a host and volume. It returns true if the connection
// was created, and false if it already existed.
func (p *hpeClient) connectHostToVolume(poolName string, volName string, hostName string) (bool, error) {
	logger.Debugf("HPE connectHostToVolume()")

	// url := api.NewURL().Path("connections").WithQuery("host_names", hostName).WithQuery("volume_names", poolName+"::"+volName)

	url := api.NewURL().Path("api", "v1", "vluns")

	req := make(map[string]any)

	req["hostname"] = hostName
	req["volumeName"] = volName
	req["lun"] = 0
	req["autoLun"] = true

	err := p.requestAuthenticated(http.MethodPost, url.URL, req, nil)
	if err != nil {
		if isHpeErrorOf(err, http.StatusBadRequest, "Connection already exists.") {
			// Do not error out if connection already exists.
			return false, nil
		}

		return false, fmt.Errorf("Failed to connect volume %q with host %q: %w", volName, hostName, err)
	}

	return true, nil
}

// disconnectHostFromVolume deletes a connection between a host and volume.
func (p *hpeClient) disconnectHostFromVolume(poolName string, volName string, hostName string) error {
	logger.Debugf("HPE disconnectHostFromVolume()")

	// url := api.NewURL().Path("connections").WithQuery("host_names", hostName).WithQuery("volume_names", poolName+"::"+volName)

	vlun, errVLUN := p.getVLUN(volName)
	if errVLUN != nil {
		return fmt.Errorf("HPE Error %w", errVLUN)
	}

	customParam := volName + "," + strconv.Itoa(vlun.LUN) + "," + hostName
	url := api.NewURL().UnEncodedPath("api", "v1", "vluns", customParam)

	err := p.requestAuthenticated(http.MethodDelete, url.URL, nil, nil)
	if err != nil {
		if isHpeErrorNotFound(err) {
			return api.StatusErrorf(http.StatusNotFound, "Connection between host %q and volume %q not found", volName, hostName)
		}

		return fmt.Errorf("Failed to disconnect volume %q from host %q: %w", volName, hostName, err)
	}

	return nil
}

func (p *hpeClient) getTarget() (targetNQN string, targetAddrs []string, err error) {
	logger.Debugf("HPE getTarget()")

	connector, err := p.driver.connector()
	if err != nil {
		return "", nil, err
	}
	mode := connector.Type()

	// Get HPE Storage service name based on the configured mode.
	service, ok := hpeServiceNameMapping[mode]
	if !ok {
		return "", nil, fmt.Errorf("Failed to determine service name for HPE Storage mode %q", mode)
	}
	logger.Debugf("HPE mode: %s", service)

	var portData hpeRespMembers[hpePort]
	var portMembers []string

	apiPorts := api.NewURL().Path("api", "v1", "ports")

	err = p.requestAuthenticated(http.MethodGet, apiPorts.URL, nil, &portData)
	if err != nil {
		return "", nil, fmt.Errorf("failed to retrieve port list: %w", err)
	}

	if len(portData.Members) == 0 {
		return "", nil, fmt.Errorf("HPE no port data found")
	}

	for _, member := range portData.Members {
		if member.LinkState != 4 {
			continue // skip down or unlinked ports
		}

		switch mode {
		case connectors.TypeISCSI:
			if member.Protocol != 2 {
				continue
			}
			if member.NodeWWN != "" {
				portMembers = append(portMembers, member.NodeWWN)
			}

		case connectors.TypeNVME:
			if member.Protocol != 6 {
				continue
			}
			if member.NodeWWN != "" {
				portMembers = append(portMembers, member.NodeWWN)
			}
		}
	}
	logger.Debugf("HPE retrieved WSAPI target addresses %s", portMembers)

	// // Retrieve the list of HPE Storage network interfaces.
	// interfaces, err := p.getNetworkInterfaces(service)
	// if err != nil {
	// 	return "", nil, err
	// }

	// if len(interfaces) == 0 {
	// 	return "", nil, api.StatusErrorf(http.StatusNotFound, "Enabled network interface with %q service not found", service)
	// }

	// First check if target addresses are configured, otherwise, use the discovered ones.
	var configAddrs = shared.SplitNTrimSpace(p.driver.config["hpe.target.addresses"], ",", -1, true)
	if len(configAddrs) > 0 {
		targetAddrs = configAddrs
		logger.Debugf("HPE using already configured driver hpe.target.addresses: %s", targetAddrs)
		// targetAddrs = make([]string, 0, len(interfaces))
		// for _, iface := range interfaces {
		// 	targetAddrs = append(targetAddrs, iface.Ethernet.Address)
		// }
	} else {
		targetAddrs = portMembers
		logger.Debugf("HPE using WSAPI target addresses: %s", targetAddrs)
	}

	var hpeRespSystem struct {
		Name string `json:"name"`
	}

	apiSystem := api.NewURL().Path("api", "v1", "system")

	err = p.requestAuthenticated(http.MethodGet, apiSystem.URL, nil, &hpeRespSystem)
	if err != nil {
		return "", nil, fmt.Errorf("HPE failed to retrieve WSAPI System data: %w", err)
	}

	if p.driver.config["hpe.target.nqn"] != "" {
		targetNQN = p.driver.config["hpe.target.nqn"]
		logger.Debugf("HPE using already configured hpe.target.nqn: %s", targetNQN)
	} else {
		targetNQN = hpeRespSystem.Name
		logger.Debugf("HPE using WSAPI target NQN: %s", targetNQN)
	}

	if targetNQN == "" || len(targetAddrs) == 0 {
		return "", nil, fmt.Errorf("HPE no usable target found for mode %q", mode)
	}

	// targetAddrs = nil
	// targetAddrs = append(targetAddrs, "127.0.0.1")
	// logger.Debugf("HPE found Target Addressess: %s", targetAddrs)

	return targetNQN, targetAddrs, nil
}

// ensureHost returns a name of the host that is configured with a given IQN. If such host
// does not exist, a new one is created, where host's name equals to the server name with a
// mode included as a suffix because HPE Storage does not allow mixing IQNs, NQNs, and WWNs
// on a single host.
func (d *hpe) ensureHost() (hostName string, cleanup revert.Hook, err error) {
	logger.Debugf("HPE ensureHost()")

	var hostname string

	revert := revert.New()
	defer revert.Fail()

	connector, err := d.connector()
	if err != nil {
		return "", nil, err
	}

	// Get the qualified name of the host.
	qn, err := connector.QualifiedName()
	if err != nil {
		return "", nil, err
	}

	// Fetch an existing HPE Storage host.
	host, err := d.client().getCurrentHost()
	if err != nil {
		if !api.StatusErrorCheck(err, http.StatusNotFound) {
			return "", nil, err
		}

		// The HPE Storage host with a qualified name of the current LXD host does not exist.
		// Therefore, create a new one and name it after the server name.
		serverName, err := ResolveServerName(d.state.ServerName)
		if err != nil {
			return "", nil, err
		}

		// Append the mode to the server name because HPE Storage does not allow mixing
		// NQNs, IQNs, and WWNs for a single host.
		hostname = serverName + "-" + connector.Type()

		err = d.client().createHost(hostname, qn)
		if err != nil {
			if !api.StatusErrorCheck(err, http.StatusConflict) {
				return "", nil, err
			}

			// The host with the given name already exists, update it instead.
			err = d.client().updateHost(hostname, qn)
			if err != nil {
				return "", nil, err
			}
		} else {
			revert.Add(func() { _ = d.client().deleteHost(hostname) })
		}
	} else {
		// Hostname already exists with the given IQN.
		hostname = host.Name
	}

	cleanup = revert.Clone().Fail
	revert.Success()
	return hostname, cleanup, nil
}

// mapVolume maps the given volume onto this host.
func (d *hpe) mapVolume(vol Volume) (cleanup revert.Hook, err error) {
	logger.Debugf("HPE mapVolume()")

	reverter := revert.New()
	defer reverter.Fail()

	connector, err := d.connector()
	if err != nil {
		return nil, err
	}

	volName, err := d.getVolumeName(vol)
	if err != nil {
		return nil, err
	}

	unlock, err := remoteVolumeMapLock(connector.Type(), "hpe")
	if err != nil {
		return nil, err
	}

	defer unlock()

	// Ensure the host exists and is configured with the correct QN.
	hostname, cleanup, err := d.ensureHost()
	if err != nil {
		return nil, err
	}

	reverter.Add(cleanup)

	// Ensure the volume is connected to the host.
	connCreated, err := d.client().connectHostToVolume(vol.pool, volName, hostname)
	if err != nil {
		return nil, err
	}

	if connCreated {
		reverter.Add(func() { _ = d.client().disconnectHostFromVolume(vol.pool, volName, hostname) })
	}

	// Find the array's qualified name for the configured mode.
	targetNQN, targetAddrs, err := d.client().getTarget()
	if err != nil {
		return nil, err
	}

	// Connect to the array.
	connReverter, err := connector.Connect(d.state.ShutdownCtx, targetNQN, targetAddrs...)
	if err != nil {
		return nil, err
	}

	reverter.Add(connReverter)

	// If connect succeeded it means we have at least one established connection.
	// However, it's reverter does not cleanup the establised connections or a newly
	// created session. Therefore, if we created a mapping, add unmapVolume to the
	// returned (outer) reverter. Unmap ensures the target is disconnected only when
	// no other device is using it.
	outerReverter := revert.New()
	if connCreated {
		outerReverter.Add(func() { _ = d.unmapVolume(vol) })
	}

	// Add connReverter to the outer reverter, as it will immediately stop
	// any ongoing connection attempts. Note that it must be added after
	// unmapVolume to ensure it is called first.
	outerReverter.Add(connReverter)

	reverter.Success()

	return outerReverter.Fail, nil
}

// unmapVolume unmaps the given volume from this host.
func (d *hpe) unmapVolume(vol Volume) error {
	logger.Debugf("HPE unmapVolume()")

	connector, err := d.connector()
	if err != nil {
		return err
	}

	volName, err := d.getVolumeName(vol)
	if err != nil {
		return err
	}

	unlock, err := remoteVolumeMapLock(connector.Type(), "hpe")
	if err != nil {
		return err
	}

	defer unlock()

	host, err := d.client().getCurrentHost()
	if err != nil {
		return err
	}

	// Disconnect the volume from the host and ignore error if connection does not exist.
	err = d.client().disconnectHostFromVolume(vol.pool, volName, host.Name)
	if err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
		return err
	}

	volumePath, _, _ := d.getMappedDevPath(vol, false)
	if volumePath != "" {
		// When iSCSI volume is disconnected from the host, the device will remain on the system.
		//
		// To remove the device, we need to either logout from the session or remove the
		// device manually. Logging out of the session is not desired as it would disconnect
		// from all connected volumes. Therefore, we need to manually remove the device.
		if connector.Type() == connectors.TypeISCSI {
			// removeDevice removes device from the system if the device is removable.
			removeDevice := func(devName string) error {
				path := "/sys/block/" + devName + "/device/delete"
				if shared.PathExists(path) {
					// Delete device.
					err := os.WriteFile(path, []byte("1"), 0400)
					if err != nil {
						return err
					}
				}
				return nil
			}

			devName := filepath.Base(volumePath)
			if strings.HasPrefix(devName, "dm-") {
				// Multipath device (/dev/dm-*) itself is not removable.
				// Therefore, we remove its slaves instead.
				slaves, err := filepath.Glob("/sys/block/" + devName + "/slaves/*")
				if err != nil {
					return fmt.Errorf("Failed to unmap volume %q: Failed to list slaves for device %q: %w", vol.name, devName, err)
				}

				// Remove slave devices.
				for _, slave := range slaves {
					slaveDevName := filepath.Base(slave)

					err := removeDevice(slaveDevName)
					if err != nil {
						return fmt.Errorf("Failed to unmap volume %q: Failed to remove slave device %q: %w", vol.name, slaveDevName, err)
					}
				}
			} else {
				// For non-multipath device (/dev/sd*), remove the device itself.
				err := removeDevice(devName)
				if err != nil {
					return fmt.Errorf("Failed to unmap volume %q: Failed to remove device %q: %w", vol.name, devName, err)
				}
			}
		}

		// Wait until the volume has disappeared.
		ctx, cancel := context.WithTimeout(d.state.ShutdownCtx, 30*time.Second)
		defer cancel()

		if !block.WaitDiskDeviceGone(ctx, volumePath) {
			return fmt.Errorf("Timeout exceeded waiting for HPE Storage volume %q to disappear on path %q", vol.name, volumePath)
		}
	}

	// If this was the last volume being unmapped from this system, disconnect the active session
	// and remove the host from HPE Storage.
	// if host.ConnectionCount <= 1 {
	targetQN, _, err := d.client().getTarget()
	if err != nil {
		return err
	}

	// Disconnect from the target.
	err = connector.Disconnect(targetQN)
	if err != nil {
		return err
	}

	// Remove the host from HPE Storage.
	err = d.client().deleteHost(host.Name)
	if err != nil {
		return err
	}
	// }

	return nil
}

// getMappedDevPath returns the local device path for the given volume.
// Indicate with mapVolume if the volume should get mapped to the system if it isn't present.
func (d *hpe) getMappedDevPath(vol Volume, mapVolume bool) (string, revert.Hook, error) {
	logger.Debugf("HPE getMappedDevPath()")

	revert := revert.New()
	defer revert.Fail()

	connector, err := d.connector()
	if err != nil {
		return "", nil, err
	}

	if mapVolume {
		cleanup, err := d.mapVolume(vol)
		if err != nil {
			return "", nil, err
		}
		revert.Add(cleanup)
	}

	volName, err := d.getVolumeName(vol)
	if err != nil {
		return "", nil, err
	}

	hpeVol, err := d.client().getVolume(vol.pool, volName)
	if err != nil {
		return "", nil, err
	}

	// Ensure the serial number is exactly 24 characters long, as it uniquely
	// identifies the device. This check should never succeed, but prevents
	// out-of-bounds errors when slicing the string later.
	if len(hpeVol.Serial) != 24 {
		return "", nil, fmt.Errorf("Failed to locate device for volume %q: Unexpected length of serial number %q (%d)", vol.name, hpeVol.Serial, len(hpeVol.Serial))
	}

	var diskPrefix string
	var diskSuffix string

	switch connector.Type() {
	case connectors.TypeISCSI:
		diskPrefix = "scsi-"
		diskSuffix = hpeVol.Serial
	case connectors.TypeNVME:
		diskPrefix = "nvme-eui."

		// The disk device ID (e.g. "008726b5033af24324a9373d00014196") is constructed as:
		// - "00"             - Padding
		// - "8726b5033af243" - First 14 characters of serial number
		// - "24a937"         - OUI (Organizationally Unique Identifier)
		// - "3d00014196"     - Last 10 characters of serial number
		diskSuffix = "00" + hpeVol.Serial[0:14] + "24a937" + hpeVol.Serial[14:]
	default:
		return "", nil, fmt.Errorf("Unsupported HPE Storage mode %q", connector.Type())
	}

	// Filters devices by matching the device path with the lowercase disk suffix.
	// HPE Storage reports serial numbers in uppercase, so the suffix is converted
	// to lowercase.
	diskPathFilter := func(devPath string) bool {
		return strings.HasSuffix(devPath, strings.ToLower(diskSuffix))
	}

	var devicePath string
	if mapVolume {
		// Wait until the disk device is mapped to the host.
		devicePath, err = block.WaitDiskDevicePath(d.state.ShutdownCtx, diskPrefix, diskPathFilter)
	} else {
		// Expect device to be already mapped.
		devicePath, err = block.GetDiskDevicePath(diskPrefix, diskPathFilter)
	}

	if err != nil {
		return "", nil, fmt.Errorf("Failed to locate device for volume %q: %w", vol.name, err)
	}

	cleanup := revert.Clone().Fail

	revert.Success()

	return devicePath, cleanup, nil
}

// getVolumeName returns the fully qualified name derived from the volume's UUID.
func (d *hpe) getVolumeName(vol Volume) (string, error) {
	logger.Debugf("HPE getVolumeName()")

	volUUID, err := uuid.Parse(vol.config["volatile.uuid"])
	if err != nil {
		return "", fmt.Errorf(`Failed parsing "volatile.uuid" from volume %q: %w`, vol.name, err)
	}

	// Remove hypens from the UUID to create a volume name.
	volName := strings.ReplaceAll(volUUID.String(), "-", "")

	// Search for the volume type prefix, and if found, prepend it to the volume name.
	volumeTypePrefix, ok := hpeVolTypePrefixes[vol.volType]
	if ok {
		volName = volumeTypePrefix + "-" + volName
	}

	// Search for the content type suffix, and if found, append it to the volume name.
	contentTypeSuffix, ok := hpeContentTypeSuffixes[vol.contentType]
	if ok {
		volName = volName + "-" + contentTypeSuffix
	}

	// If volume is snapshot, prepend snapshot prefix to its name.
	if vol.IsSnapshot() {
		volName = hpeSnapshotPrefix + volName
	}

	return volName, nil
}
