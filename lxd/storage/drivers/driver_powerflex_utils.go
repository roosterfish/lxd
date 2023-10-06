package drivers

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/canonical/lxd/lxd/locking"
	"github.com/canonical/lxd/lxd/resources"
	"github.com/canonical/lxd/lxd/revert"
	"github.com/canonical/lxd/lxd/util"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
)

// powerFlexBlockVolSuffix suffix used for block content type volumes.
const powerFlexBlockVolSuffix = ".b"

// powerFlexISOVolSuffix suffix used for iso content type volumes.
const powerFlexISOVolSuffix = ".i"

// powerFlexCodeVolumeNotFound is returned by the API in case a storage volume does not exist.
const powerFlexCodeVolumeNotFound = 79

type powerFlexVolumeType string
type powerFlexSnapshotMode string

const powerFlexVolumeThin powerFlexVolumeType = "ThinProvisioned"
const powerFlexVolumeThick powerFlexVolumeType = "ThickProvisioned"

const powerFlexSnapshotRW powerFlexSnapshotMode = "ReadWrite"

// powerFlexVolTypePrefixes maps volume type to storage volume name prefix.
// Use smallest possible prefixes since PowerFlex volume names are limited to 31 characters.
var powerFlexVolTypePrefixes = map[VolumeType]string{
	VolumeTypeContainer: "c",
	VolumeTypeVM:        "v",
	VolumeTypeImage:     "i",
	VolumeTypeCustom:    "u",
}

// powerFlexError contains arbitrary error responses from PowerFlex.
type powerFlexError map[string]any

// Error tries to return all kinds of errors from the PowerFlex API in a nicely formatted way.
func (p *powerFlexError) Error() string {
	var errorStrings []string
	for k, v := range *p {
		errorStrings = append(errorStrings, fmt.Sprintf("%s: %v", k, v))
	}

	return strings.Join(errorStrings, ", ")
}

// ErrorCode extracts the errorCode value from a PowerFlex response.
func (p *powerFlexError) ErrorCode() float64 {
	code, ok := (*p)["errorCode"].(float64)
	if !ok {
		return 0
	}

	return code
}

// HTTPStatusCode extracts the httpStatusCode value from a PowerFlex response.
func (p *powerFlexError) HTTPStatusCode() float64 {
	code, ok := (*p)["httpStatusCode"].(float64)
	if !ok {
		return 0
	}

	return code
}

// powerFlexStoragePool represents a storage pool in PowerFlex.
type powerFlexStoragePool struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	ProtectionDomainID string `json:"protectionDomainId"`
}

// powerFlexProtectionDomain represents a protection domain in PowerFlex.
type powerFlexProtectionDomain struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	SystemID string `json:"systemId"`
}

// powerFlexProtectionDomainSDSRelation represents an SDS related to a protection domain in PowerFlex.
type powerFlexProtectionDomainSDTRelation struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IPList []struct {
		IP string `json:"ip"`
	} `json:"ipList"`
}

// powerFlexSDC represents a SDC in PowerFlex.
type powerFlexSDC struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	HostType string `json:"hostType"`
	NQN      string `json:"nqn"`
}

// powerFlexVolume represents a volume in PowerFlex.
type powerFlexVolume struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	VolumeType       string `json:"volumeType"`
	VTreeID          string `json:"vtreeId"`
	AncestorVolumeID string `json:"ancestorVolumeId"`
	MappedSDCInfo    []struct {
		SDCID    string `json:"sdcId"`
		SDCName  string `json:"sdcName"`
		NQN      string `json:"nqn"`
		HostType string `json:"hostType"`
	} `json:"mappedSdcInfo"`
}

// powerFlexClient holds the PowerFlex HTTP client and an access token factory.
type powerFlexClient struct {
	driver *powerflex
	token  *util.TokenFactory
}

// newPowerFlexClient creates a new instance of the HTTP PowerFlex client.
func newPowerFlexClient(driver *powerflex) *powerFlexClient {
	return &powerFlexClient{
		driver: driver,
		token:  util.NewTokenFactory(),
	}
}

// createBodyReader creates a reader for the given request body contents.
func (p *powerFlexClient) createBodyReader(contents map[string]any) (io.Reader, error) {
	body := &bytes.Buffer{}
	encoder := json.NewEncoder(body)
	err := encoder.Encode(contents)
	if err != nil {
		return nil, fmt.Errorf("Failed to write request body: %w", err)
	}

	return body, nil
}

// request issues a HTTP request against the PowerFlex gateway.
func (p *powerFlexClient) request(method string, path string, body io.Reader, response any) error {
	url := fmt.Sprintf("%s%s", p.driver.config["powerflex.gateway"], path)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("Failed to create login request: %w", err)
	}

	req.Header.Add("Accept", "application/json")
	if body != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	token := p.token.Get()
	if token != "" {
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: shared.IsFalse(p.driver.config["powerflex.gateway.verify"]),
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to send request: %w", err)
	}

	defer resp.Body.Close()

	// Overwrite the response data type if an error is detected.
	if resp.StatusCode != 200 {
		response = &powerFlexError{}
	}

	if response != nil {
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(response)
		if err != nil {
			return fmt.Errorf("Failed to read response body: %s: %w", path, err)
		}
	}

	// Return the formatted error from the body
	powerFlexErr, ok := response.(*powerFlexError)
	if ok {
		return powerFlexErr
	}

	return nil
}

// requestAuthenticated issues an authenticated HTTP request against the PowerFlex gateway.
func (p *powerFlexClient) requestAuthenticated(method string, path string, body io.Reader, response any) error {
	err := p.login()
	if err != nil {
		return err
	}

	return p.request(method, path, body, response)
}

// login creates a new access token and authenticates the client.
func (p *powerFlexClient) login() error {
	if p.token.Get() != "" {
		return nil
	}

	body, err := p.createBodyReader(map[string]any{
		"username": p.driver.config["powerflex.user.name"],
		"password": p.driver.config["powerflex.user.password"],
	})
	if err != nil {
		return err
	}

	var actualResponse struct {
		AccessToken string        `json:"access_token"`
		ExpiresIn   time.Duration `json:"expires_in"`
	}

	err = p.request(http.MethodPost, "/rest/auth/login", body, &actualResponse)
	if err != nil {
		return fmt.Errorf("Failed to login: %w", err)
	}

	// Expire the token after half of its lifetime
	p.token.Set(actualResponse.AccessToken, time.Now().Add(actualResponse.ExpiresIn*time.Second/2))
	return nil
}

// getStoragePool returns the storage pool behind poolID.
func (p *powerFlexClient) getStoragePool(poolID string) (*powerFlexStoragePool, error) {
	var actualResponse powerFlexStoragePool
	err := p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/StoragePool::%s", poolID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get storage pool: %q: %w", poolID, err)
	}

	return &actualResponse, nil
}

// getProtectionDomain returns the protection domain behind domainID.
func (p *powerFlexClient) getProtectionDomain(domainID string) (*powerFlexProtectionDomain, error) {
	var actualResponse powerFlexProtectionDomain
	err := p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/ProtectionDomain::%s", domainID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get protection domain: %q: %w", domainID, err)
	}

	return &actualResponse, nil
}

// getProtectionDomainSDTRelations returns the protection domains SDT relations.
func (p *powerFlexClient) getProtectionDomainSDTRelations(domainID string) ([]powerFlexProtectionDomainSDTRelation, error) {
	var actualResponse []powerFlexProtectionDomainSDTRelation
	err := p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/ProtectionDomain::%s/relationships/Sdt", domainID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get protection domain SDT relations: %q: %w", domainID, err)
	}

	return actualResponse, nil
}

// getVolumeID returns the volume ID for the given name.
func (p *powerFlexClient) getVolumeID(name string) (string, error) {
	body, err := p.createBodyReader(map[string]any{
		"name": name,
	})
	if err != nil {
		return "", err
	}

	var actualResponse string
	err = p.requestAuthenticated(http.MethodPost, "/api/types/Volume/instances/action/queryIdByKey", body, &actualResponse)
	if err != nil {
		powerFlexError, ok := err.(*powerFlexError)
		if ok {
			// API returns 500 if the volume does not exist.
			// To not confuse it with other 500 that might occur check the error code too.
			if powerFlexError.HTTPStatusCode() == http.StatusInternalServerError && powerFlexError.ErrorCode() == powerFlexCodeVolumeNotFound {
				return "", api.StatusErrorf(http.StatusNotFound, "PowerFlex volume not found: %q", name)
			}
		}

		return "", fmt.Errorf("Failed to get volume ID: %q: %w", name, err)
	}

	return actualResponse, nil
}

// getVolume returns the volume behind volumeID.
func (p *powerFlexClient) getVolume(volumeID string) (*powerFlexVolume, error) {
	var actualResponse powerFlexVolume
	err := p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/Volume::%s", volumeID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get volume: %q: %w", volumeID, err)
	}

	return &actualResponse, nil
}

// createVolume creates a new volume.
// The size needs to be a number in multiples of 8.
// The unit used by PowerFlex is GiB.
// The returned string represents the ID of the volume.
func (p *powerFlexClient) createVolume(volumeName string, sizeGiB int64, volumeType powerFlexVolumeType, poolID string) (string, error) {
	stringSize := strconv.FormatInt(sizeGiB, 10)
	body, err := p.createBodyReader(map[string]any{
		"name":           volumeName,
		"volumeSizeInGb": stringSize,
		"volumeType":     volumeType,
		"storagePoolId":  poolID,
	})
	if err != nil {
		return "", err
	}

	var actualResponse struct {
		ID string `json:"id"`
	}

	err = p.requestAuthenticated(http.MethodPost, "/api/types/Volume/instances", body, &actualResponse)
	if err != nil {
		return "", fmt.Errorf("Failed to create volume: %q: %w", volumeName, err)
	}

	return actualResponse.ID, nil
}

// renameVolume renames the volume behind volumeID to newName.
func (p *powerFlexClient) renameVolume(volumeID string, newName string) error {
	body, err := p.createBodyReader(map[string]any{
		"newName": newName,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/setVolumeName", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to rename volume: %q: %w", volumeID, err)
	}

	return nil
}

// setVolumeSize sets the size of the volume behind volumeID to size.
// The size needs to be a number in multiples of 8.
// The unit used by PowerFlex is GiB.
func (p *powerFlexClient) setVolumeSize(volumeID string, sizeGiB int64) error {
	stringSize := strconv.FormatInt(sizeGiB, 10)
	body, err := p.createBodyReader(map[string]any{
		"sizeInGB": stringSize,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/setVolumeSize", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to set volume size: %q: %w", volumeID, err)
	}

	return nil
}

// overwriteVolume overwrites the volumes contents behind volumeID with the given snapshot.
func (p *powerFlexClient) overwriteVolume(volumeID string, snapshotID string) error {
	body, err := p.createBodyReader(map[string]any{
		"srcVolumeId": snapshotID,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/overwriteVolumeContent", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to overwrite volume: %q: %w", volumeID, err)
	}

	return nil
}

// createVolumeSnapshot creates a new volume snapshot under the given systemID for the volume behind volumeID.
// The accessMode can be either ReadWrite or ReadOnly.
// The returned string represents the ID of the snapshot.
func (p *powerFlexClient) createVolumeSnapshot(systemID string, volumeID string, snapshotName string, accessMode powerFlexSnapshotMode) (string, error) {
	body, err := p.createBodyReader(map[string]any{
		"snapshotDefs": []map[string]string{
			{
				"volumeId":     volumeID,
				"snapshotName": snapshotName,
			},
		},
		"accessModeLimit": accessMode,
	})
	if err != nil {
		return "", err
	}

	var actualResponse struct {
		VolumeIDs []string `json:"volumeIdList"`
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/System::%s/action/snapshotVolumes", systemID), body, &actualResponse)
	if err != nil {
		return "", fmt.Errorf("Failed to create volume snapshot: %q: %w", snapshotName, err)
	}

	if len(actualResponse.VolumeIDs) == 0 {
		return "", fmt.Errorf("Response does not contain a single snapshot ID")
	}

	return actualResponse.VolumeIDs[0], nil
}

// getVolumeSnapshots returns the snapshots of the volume behind volumeID.
func (p *powerFlexClient) getVolumeSnapshots(volumeID string) ([]powerFlexVolume, error) {
	volume, err := p.getVolume(volumeID)
	if err != nil {
		return nil, err
	}

	var actualResponse []powerFlexVolume
	err = p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/VTree::%s/relationships/Volume", volume.VTreeID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get volume snapshots: %q: %w", volumeID, err)
	}

	var filteredVolumes []powerFlexVolume
	for _, volume := range actualResponse {
		if volume.AncestorVolumeID == volumeID {
			filteredVolumes = append(filteredVolumes, volume)
		}
	}

	return filteredVolumes, nil
}

// deleteVolume deletes the volume behind volumeID.
// The deleteMode can be one of ONLY_ME, INCLUDING_DESCENDANTS, DESCENDANTS_ONLY or WHOLE_VTREE.
// It describes the impact when deleting a volume from the underlying VTree. ONLY_ME deletes the
// provided volume only whereas WHOLE_VTREE also deletes the volumes parent(s) and child(s).
func (p *powerFlexClient) deleteVolume(volumeID string, deleteMode string) error {
	body, err := p.createBodyReader(map[string]any{
		"removeMode": deleteMode,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/removeVolume", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete volume: %q: %w", volumeID, err)
	}

	return nil
}

// getHosts returns all hosts.
func (p *powerFlexClient) getHosts() ([]powerFlexSDC, error) {
	var actualResponse []powerFlexSDC
	err := p.requestAuthenticated(http.MethodGet, "/api/types/Sdc/instances", nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get hosts: %w", err)
	}

	return actualResponse, nil
}

// getNVMeHosts returns all NVMe hosts.
func (p *powerFlexClient) getNVMeHosts() ([]powerFlexSDC, error) {
	allHosts, err := p.getHosts()
	if err != nil {
		return nil, err
	}

	var nvmeHosts []powerFlexSDC
	for _, host := range allHosts {
		if host.HostType == "NVMeHost" {
			nvmeHosts = append(nvmeHosts, host)
		}
	}

	return nvmeHosts, nil
}

// getNVMeHostByNQN returns the NVMe host matching the nqn.
func (p *powerFlexClient) getNVMeHostByNQN(nqn string) (*powerFlexSDC, error) {
	allNVMeHosts, err := p.getNVMeHosts()
	if err != nil {
		return nil, err
	}

	for _, host := range allNVMeHosts {
		if host.NQN == nqn {
			return &host, nil
		}
	}

	return nil, api.StatusErrorf(http.StatusNotFound, "Host not found using nqn: %q", nqn)
}

// createHost creates a new host.
func (p *powerFlexClient) createHost(hostName string, nqn string) (string, error) {
	body, err := p.createBodyReader(map[string]any{
		"name": hostName,
		"nqn":  nqn,
	})
	if err != nil {
		return "", err
	}

	var actualResponse struct {
		ID string `json:"id"`
	}

	err = p.requestAuthenticated(http.MethodPost, "/api/types/Host/instances", body, &actualResponse)
	if err != nil {
		return "", fmt.Errorf("Failed to create host: %w", err)
	}

	return actualResponse.ID, nil
}

// deleteHost deletes the host behind hostID.
func (p *powerFlexClient) deleteHost(hostID string) error {
	err := p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Sdc::%s/action/removeSdc", hostID), nil, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete host: %w", err)
	}

	return nil
}

// createHostVolumeMapping creates the mapping between a host and volume.
func (p *powerFlexClient) createHostVolumeMapping(hostID string, volumeID string) error {
	body, err := p.createBodyReader(map[string]any{
		"hostId": hostID,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/addMappedHost", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to create host volume mapping between %q and %q: %w", hostID, volumeID, err)
	}

	return nil
}

// deleteHostVolumeMapping deletes the mapping between a host and volume.
func (p *powerFlexClient) deleteHostVolumeMapping(hostID string, volumeID string) error {
	body, err := p.createBodyReader(map[string]any{
		"hostId": hostID,
	})
	if err != nil {
		return err
	}

	err = p.requestAuthenticated(http.MethodPost, fmt.Sprintf("/api/instances/Volume::%s/action/removeMappedHost", volumeID), body, nil)
	if err != nil {
		return fmt.Errorf("Failed to delete host volume mapping between %q and %q: %w", hostID, volumeID, err)
	}

	return nil
}

// getHostVolumeMappings returns the volume mappings for the host behind hostID.
func (p *powerFlexClient) getHostVolumeMappings(hostID string) ([]powerFlexVolume, error) {
	var actualResponse []powerFlexVolume
	err := p.requestAuthenticated(http.MethodGet, fmt.Sprintf("/api/instances/Sdc::%s/relationships/Volume", hostID), nil, &actualResponse)
	if err != nil {
		return nil, fmt.Errorf("Failed to get host volume mappings: %w", err)
	}

	return actualResponse, nil
}

// canNVMe returns true if this node supports the PowerFlex NVMe mode.
func (d *powerflex) canNVMe() bool {
	err := util.LoadModule("nvme_fabrics")
	if err != nil {
		return false
	}

	err = util.LoadModule("nvme_tcp")
	return err == nil
}

// client returns the drivers PowerFlex client.
// A new client gets created if it not yet exists.
func (d *powerflex) client() *powerFlexClient {
	if d.httpClient == nil {
		d.httpClient = newPowerFlexClient(d)
	}

	return d.httpClient
}

// getHostNQN returns the unique NVMe nqn for the current host.
// A custom one is generated from the servers UUID since getting the nqn from /etc/nvme/hostnqn
// requires the nvme-cli package to be installed on the host.
func (d *powerflex) getHostNQN() string {
	return fmt.Sprintf("nqn.2014-08.org.nvmexpress:uuid:%s", d.state.ServerUUID)
}

// getServerName returns the hostname of this host.
// It prefers the value from the daemons state in case LXD is clustered.
func (d *powerflex) getServerName() (string, error) {
	if d.state.ServerName != "none" {
		return d.state.ServerName, nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("Failed to get hostname: %w", err)
	}

	return hostname, nil
}

// getVolumeType returns the selected provisioning type of the volume.
// As a default it returns type thin.
func (d *powerflex) getVolumeType(vol Volume) powerFlexVolumeType {
	var volumeType string
	if vol.config["block.type"] != "" {
		volumeType = vol.config["block.type"]
	}

	if volumeType == "thick" {
		return powerFlexVolumeThick
	}

	return powerFlexVolumeThin
}

// getVolumeName returns the fully qualified name derived from the volume.
func (d *powerflex) getVolumeName(vol Volume) string {
	var out string
	parentName, snapshotName, isSnapshot := api.GetParentAndSnapshotName(vol.name)

	// Only use filesystem suffix on filesystem type image volumes (for all content types).
	// Since PowerFlex volumes can be 31 characters long at max, use the image fingerprint.
	if vol.volType == VolumeTypeImage {
		parentName = fmt.Sprintf("%s_%s", parentName[0:12], vol.ConfigBlockFilesystem())
	}

	if vol.contentType == ContentTypeBlock {
		parentName = fmt.Sprintf("%s%s", parentName, powerFlexBlockVolSuffix)
	} else if vol.contentType == ContentTypeISO {
		parentName = fmt.Sprintf("%s%s", parentName, powerFlexISOVolSuffix)
	}

	// Use volume's type as storage volume prefix, unless there is an override in powerFlexVolTypePrefixes.
	volumeTypePrefix := string(vol.volType)
	volumeTypePrefixOverride, foundOveride := powerFlexVolTypePrefixes[vol.volType]
	if foundOveride {
		volumeTypePrefix = volumeTypePrefixOverride
	}

	if isSnapshot {
		// If volumeName is a snapshot (<vol>/<snap>) and snapName is not set,
		// assume that it's a normal snapshot add @snapNumber.
		out = fmt.Sprintf("%s_%s@%s", volumeTypePrefix, parentName, strings.Trim(snapshotName, "snap"))
	} else {
		out = fmt.Sprintf("%s_%s", volumeTypePrefix, parentName)
	}

	return out
}

// createNVMeHost creates this NVMe host in PowerFlex.
// The operation is idempotent and locked using lock name powerflex.host.
func (d *powerflex) createNVMeHost() (string, error) {
	unlock, err := locking.Lock(d.state.ShutdownCtx, "powerflex.host")
	if err != nil {
		return "", err
	}

	defer unlock()

	var hostID string
	nqn := d.getHostNQN()

	client := d.client()
	host, err := client.getNVMeHostByNQN(nqn)
	if err != nil {
		if !api.StatusErrorCheck(err, http.StatusNotFound) {
			return "", err
		}

		hostname, err := d.getServerName()
		if err != nil {
			return "", err
		}

		hostID, err = client.createHost(hostname, nqn)
		if err != nil {
			return "", err
		}
	}

	if hostID == "" {
		hostID = host.ID
	}

	return hostID, nil
}

// deleteNVMeHost delets this NVMe host in PowerFlex.
// The operation is idempotent and locked using lock name powerflex.host.
func (d *powerflex) deleteNVMeHost() error {
	unlock, err := locking.Lock(d.state.ShutdownCtx, "powerflex.host")
	if err != nil {
		return err
	}

	defer unlock()

	client := d.client()
	nqn := d.getHostNQN()
	host, err := client.getNVMeHostByNQN(nqn)
	if err != nil {
		// Skip the deletion if the host doesn't exist anymore.
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}

		return err
	}

	return client.deleteHost(host.ID)
}

// mapNVMeVolume maps the given volume onto this host.
func (d *powerflex) mapNVMeVolume(volumeName string) (revert.Hook, error) {
	revert := revert.New()
	defer revert.Fail()

	hostID, err := d.createNVMeHost()
	if err != nil {
		return nil, err
	}

	client := d.client()
	volumeID, err := client.getVolumeID(volumeName)
	if err != nil {
		return nil, err
	}

	volume, err := client.getVolume(volumeID)
	if err != nil {
		return nil, err
	}

	mapped := false
	for _, mapping := range volume.MappedSDCInfo {
		if mapping.SDCID == hostID {
			mapped = true
		}
	}

	if !mapped {
		err = client.createHostVolumeMapping(hostID, volumeID)
		if err != nil {
			return nil, err
		}

		revert.Add(func() { _ = client.deleteHostVolumeMapping(hostID, volumeID) })
	}

	cleanup := revert.Clone().Fail
	revert.Success()
	return cleanup, nil
}

// getNVMeMappedDevPath returns the local device path for the given NVMe volume name.
// Set mapVolume to true if the volume isn't already mapped to this host.
func (d *powerflex) getNVMeMappedDevPath(volumeName string, mapVolume bool) (string, revert.Hook, error) {
	revert := revert.New()
	defer revert.Fail()

	if mapVolume {
		cleanup, err := d.mapNVMeVolume(volumeName)
		if err != nil {
			return "", nil, err
		}

		revert.Add(cleanup)

		// Connect to the NVMe/TCP subsystem.
		// We have to connect after the first mapping was established.
		// PowerFlex does not offer any discovery log entries until a volume gets mapped to the host.
		// This action is idempotent.
		err = d.connectNVMeSubsys()
		if err != nil {
			return "", nil, err
		}
	}

	powerFlexVolumes := make(map[string]string)
	discoverFunc := func(volumeID string) error {
		diskPaths, err := resources.GetDisksByID(fmt.Sprintf("nvme-eui.%s", volumeID))
		if err != nil {
			return err
		}

		for _, diskPath := range diskPaths {
			// Skip the disk if it is only a partition of the actual PowerFlex volume.
			if strings.Contains(diskPath, "-part") {
				continue
			}

			// TODO: run in a loop since the actual /dev/device might not already be there
			devPath, err := filepath.EvalSymlinks(diskPath)
			if err != nil {
				return fmt.Errorf("Failed resolving disks device link: %w", err)
			}

			powerFlexVolumes[volumeID] = devPath
		}

		return nil
	}

	powerFlexVolumeID, err := d.client().getVolumeID(volumeName)
	if err != nil {
		return "", nil, err
	}

	timeout := time.Now().Add(10 * time.Second)

	for {
		err := discoverFunc(powerFlexVolumeID)
		if err != nil {
			return "", nil, err
		}

		_, ok := powerFlexVolumes[powerFlexVolumeID]
		if ok {
			break
		}

		if time.Now().After(timeout) {
			return "", nil, fmt.Errorf("Timeout exceeded for NVMe volume discovery: %q", volumeName)
		}

		time.Sleep(10 * time.Millisecond)
	}

	if len(powerFlexVolumes) == 0 {
		return "", nil, fmt.Errorf("Failed to discover any NVMe volume")
	}

	powerFlexVolumePath, ok := powerFlexVolumes[powerFlexVolumeID]
	if !ok {
		return "", nil, fmt.Errorf("Volume not found: %q", volumeName)
	}

	cleanup := revert.Clone().Fail
	revert.Success()
	return powerFlexVolumePath, cleanup, nil
}

// getMappedDevPath returns the local device path for the given volume name.
func (d *powerflex) getMappedDevPath(vol Volume, mapVolume bool) (string, revert.Hook, error) {
	if d.config["powerflex.mode"] == "nvme" {
		path, cleanup, err := d.getNVMeMappedDevPath(d.getVolumeName(vol), mapVolume)
		if err != nil {
			return "", nil, err
		}

		return path, cleanup, nil
	}

	return "", nil, ErrNotSupported
}

// unmapNVMeVolume unmaps the given NVMe volume from this host.
func (d *powerflex) unmapNVMeVolume(volumeName string) error {
	client := d.client()
	volume, err := client.getVolumeID(volumeName)
	if err != nil {
		return err
	}

	nqn := d.getHostNQN()
	host, err := client.getNVMeHostByNQN(nqn)
	if err != nil {
		return err
	}

	err = client.deleteHostVolumeMapping(host.ID, volume)
	if err != nil {
		return err
	}

	mappings, err := client.getHostVolumeMappings(host.ID)
	if err != nil {
		return err
	}

	if len(mappings) == 0 {
		// Delete the host from PowerFlex if the last volume mapping got removed.
		err = d.deleteNVMeHost()
		if err != nil {
			return err
		}

		// Disconnect from NVMe subsystem.
		err = d.disconnectNVMeSubsys()
		if err != nil {
			return err
		}
	}

	return nil
}

// unmapVolume unmaps the given volume from this host.
func (d *powerflex) unmapVolume(volumeName string) error {
	if d.config["powerflex.mode"] == "nvme" {
		return d.unmapNVMeVolume(volumeName)
	}

	return ErrNotSupported
}

// connectNVMeSubsys connects this host to the NVMe subsystem configured in the storage pool.
// The operation is locked using lock name nvme.
// The connection can only be established after the first volume is mapped to this host.
func (d *powerflex) connectNVMeSubsys() error {
	unlock, err := locking.Lock(d.state.ShutdownCtx, "nvme")
	if err != nil {
		return err
	}

	defer unlock()

	stdout, err := shared.RunCommand("nvme", "list-subsys", "-o", "json")
	if err != nil {
		return fmt.Errorf("Failed getting list of NVMe/TCP subsystems: %w", err)
	}

	var allSubSystems struct {
		SubSystems []struct {
			NQN   string `json:"NQN"`
			Paths []any  `json:"Paths"`
		} `json:"Subsystems"`
	}

	decoder := json.NewDecoder(strings.NewReader(stdout))
	err = decoder.Decode(&allSubSystems)
	if err != nil {
		return fmt.Errorf("Failed to parse list of NVMe/TCP subsystems: %w", err)
	}

	pool, err := d.client().getStoragePool(d.config["powerflex.pool"])
	if err != nil {
		return err
	}

	for _, subSystem := range allSubSystems.SubSystems {
		if strings.Contains(subSystem.NQN, pool.ProtectionDomainID) {
			// Already connected to the NVMe subsystem for the storage pools protection ID.
			return nil
		}
	}

	nqn := d.getHostNQN()
	_, stderr, err := shared.RunCommandSplit(d.state.ShutdownCtx, nil, nil, "nvme", "connect-all", "-t", "tcp", "-a", d.config["powerflex.sdt"], "-q", nqn)
	if err != nil {
		return fmt.Errorf("Failed nvme connect-all: %w", err)
	}

	if stderr != "" {
		return fmt.Errorf("Failed connecting to PowerFlex NVMe/TCP subsystem: %s", stderr)
	}

	return nil
}

// disconnectNVMeSubsys disconnects this host from the NVMe subsystem.
// The operation is locked using lock name nvme.
func (d *powerflex) disconnectNVMeSubsys() error {
	unlock, err := locking.Lock(d.state.ShutdownCtx, "nvme")
	if err != nil {
		return err
	}

	defer unlock()

	_, err = shared.RunCommand("nvme", "disconnect-all")
	if err != nil {
		return fmt.Errorf("Failed disconnecting from PowerFlex NVMe/TCP subsystem: %w", err)
	}

	return nil
}
