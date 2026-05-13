package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/canonical/lxd/shared/api"
)

type netappClient struct {
	gateway    string
	username   string
	password   string
	svmName    string
	aggregate  string
	skipVerify bool
	httpClient *http.Client
}

type netappResponseData struct {
	Job *netappJob `json:"job,omitempty"`
}

type netappJob struct {
	UUID    string `json:"uuid"`
	State   string `json:"state"`
	Message string `json:"message"`
}

type netappAggregate struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	Space struct {
		BlockStorage struct {
			Size      int64 `json:"size"`
			Available int64 `json:"available"`
		} `json:"block_storage"`
	} `json:"space"`
	// SVM is populated only when the request includes svm in the fields list,
	// e.g. via aggregates?fields=...,svm. ONTAP exposes the owning SVM on the
	// aggregate record so callers can avoid an extra round-trip.
	SVM struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"svm"`
}

type netappAggregateResponse struct {
	Records []netappAggregate `json:"records"`
}

type netappNVMeServiceResponse struct {
	Records []struct {
		SVM struct {
			Name string `json:"name"`
			UUID string `json:"uuid"`
		} `json:"svm"`
	} `json:"records"`
}

// do makes an HTTP request to the ONTAP API.
func (c *netappClient) do(ctx context.Context, method string, path string, in any, out any) error {
	var body io.Reader
	if in != nil {
		reqData, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("Failed encoding ONTAP request: %w", err)
		}

		body = bytes.NewReader(reqData)
	}

	// For modifying requests, we append return_timeout=30 to attempt synchronous completion.
	url := fmt.Sprintf("%s/api%s", c.gateway, path)
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodDelete {
		if bytes.Contains([]byte(url), []byte("?")) {
			url += "&return_timeout=30"
		} else {
			url += "?return_timeout=30"
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return fmt.Errorf("Failed creating ONTAP request: %w", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Failed performing ONTAP request: %w", err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed reading ONTAP response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Wrap in api.StatusError so callers can do idempotent handling
		// of 404/409 via api.StatusErrorCheck without parsing the body.
		return api.StatusErrorf(resp.StatusCode, "ONTAP API error: %s", string(respData))
	}

	if len(respData) > 0 {
		// If the response is 202 Accepted, we extract the job UUID and wait.
		if resp.StatusCode == http.StatusAccepted {
			var jobResp netappResponseData
			err = json.Unmarshal(respData, &jobResp)
			if err != nil {
				return fmt.Errorf("Failed decoding ONTAP job response: %w", err)
			}

			if jobResp.Job != nil && jobResp.Job.UUID != "" {
				return c.waitForJob(ctx, jobResp.Job.UUID)
			}
		}

		if out != nil {
			err = json.Unmarshal(respData, out)
			if err != nil {
				return fmt.Errorf("Failed decoding ONTAP response: %w", err)
			}
		}
	}

	return nil
}

// getJob retrieves the current status of an ONTAP job.
func (c *netappClient) getJob(ctx context.Context, jobUUID string) (*netappJob, error) {
	var job netappJob
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/cluster/jobs/%s", jobUUID), nil, &job)
	if err != nil {
		return nil, err
	}

	return &job, nil
}

// waitForJob polls the ONTAP /api/cluster/jobs/{uuid} endpoint until the job succeeds or fails.
func (c *netappClient) waitForJob(ctx context.Context, jobUUID string) error {
	for {
		job, err := c.getJob(ctx, jobUUID)
		if err != nil {
			return err
		}

		switch job.State {
		case "success":
			return nil
		case "failure":
			return fmt.Errorf("ONTAP job %s failed: %s", jobUUID, job.Message)
		}

		// Wait before next poll.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// getAggregate retrieves information about the specified aggregate.
func (c *netappClient) getAggregate(ctx context.Context, name string) (*netappAggregate, error) {
	var resp netappAggregateResponse
	path := fmt.Sprintf("/storage/aggregates?name=%s&fields=uuid,space,home_node,snapmirror_label,svm", name)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Records) == 0 {
		return nil, fmt.Errorf("Aggregate %q not found", name)
	}

	return &resp.Records[0], nil
}

// getNVMeService verifies that the NVMe protocol is enabled on the given SVM.
// ONTAP returns no records when the SVM does not have the NVMe data protocol
// configured, in which case pool creation must fail early rather than at the
// first volume create.
func (c *netappClient) getNVMeService(ctx context.Context, svmName string) error {
	var resp netappNVMeServiceResponse
	path := fmt.Sprintf("/protocols/nvme/services?svm.name=%s", svmName)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return err
	}

	if len(resp.Records) == 0 {
		return fmt.Errorf("NVMe service is not enabled on SVM %q", svmName)
	}

	return nil
}

// netappFlexVol represents a NetApp FlexVol created within an SVM.
type netappFlexVol struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
	SVM  struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"svm"`
}

type netappFlexVolResponse struct {
	Records []netappFlexVol `json:"records"`
}

type netappNamespace struct {
	UUID  string `json:"uuid"`
	Name  string `json:"name"`
	NGUID string `json:"nguid"`
	Space struct {
		Size int64 `json:"size"`
	} `json:"space"`
}

type netappNamespaceResponse struct {
	Records []netappNamespace `json:"records"`
}

// createFlexVol creates a new FlexVol on the ONTAP system for our LXD volume.
func (c *netappClient) createFlexVol(ctx context.Context, name string, svmName string, aggrName string, sizeBytes int64) error {
	req := map[string]interface{}{
		"name": name,
		"svm": map[string]string{
			"name": svmName,
		},
		"aggregates": []map[string]string{
			{"name": aggrName},
		},
		"size": sizeBytes,
		"guarantee": map[string]string{
			"type": "none", // Thin provisioning
		},
		"space": map[string]interface{}{
			"fractional_reserve": 0,
		},
	}

	err := c.do(ctx, http.MethodPost, "/storage/volumes", req, nil)
	if err != nil {
		return fmt.Errorf("Failed creating FlexVol: %w", err)
	}

	return nil
}

// deleteFlexVol deletes a FlexVol from the ONTAP system.
func (c *netappClient) deleteFlexVol(ctx context.Context, uuid string) error {
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/storage/volumes/%s", uuid), nil, nil)
	if err != nil {
		return fmt.Errorf("Failed deleting FlexVol: %w", err)
	}

	return nil
}

// createNamespace creates a new NVMe namespace inside a FlexVol.
func (c *netappClient) createNamespace(ctx context.Context, flexvolName string, namespaceName string, svmName string, sizeBytes int64) error {
	req := map[string]interface{}{
		"name": fmt.Sprintf("/vol/%s/%s", flexvolName, namespaceName),
		"svm": map[string]string{
			"name": svmName,
		},
		"space": map[string]interface{}{
			"size":      sizeBytes,
			"guarantee": false, // Disable space reservation (Thin provisioning)
		},
		"os_type": "linux",
	}

	err := c.do(ctx, http.MethodPost, "/protocols/nvme/namespaces", req, nil)
	if err != nil {
		return fmt.Errorf("Failed creating NVMe namespace: %w", err)
	}

	return nil
}

// deleteNamespace deletes an NVMe namespace.
func (c *netappClient) deleteNamespace(ctx context.Context, uuid string) error {
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/protocols/nvme/namespaces/%s", uuid), nil, nil)
	if err != nil {
		return fmt.Errorf("Failed deleting NVMe namespace: %w", err)
	}

	return nil
}

// resizeFlexVol resizes a FlexVol.
func (c *netappClient) resizeFlexVol(ctx context.Context, uuid string, newSizeBytes int64) error {
	req := map[string]interface{}{
		"size": newSizeBytes,
	}

	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/storage/volumes/%s", uuid), req, nil)
	if err != nil {
		return fmt.Errorf("Failed resizing FlexVol: %w", err)
	}

	return nil
}

// resizeNamespace resizes an NVMe namespace.
func (c *netappClient) resizeNamespace(ctx context.Context, uuid string, newSizeBytes int64) error {
	req := map[string]interface{}{
		"space": map[string]interface{}{
			"size": newSizeBytes,
		},
	}

	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/protocols/nvme/namespaces/%s", uuid), req, nil)
	if err != nil {
		return fmt.Errorf("Failed resizing NVMe namespace: %w", err)
	}

	return nil
}

// getVolumeName derives the Pure Storage styled ONTAP volume name.
func (c *netappClient) getVolumeName(vol Volume) string {
	// Volume generic UUID naming follows the typical `<typePrefix>-<uuidNoHyphens>[-<contentSuffix>]` rule.
	// As we mandated UUIDVolumeNames: true, the vol.Name is already a valid UUID string from LXD logic.

	// E.g., `c-550e8400e29b41d4a716446655440000` or `v-550e8400e29b41d4a716446655440000-b`

	var prefix string
	switch vol.volType {
	case VolumeTypeContainer:
		prefix = "c"
	case VolumeTypeVM:
		prefix = "v"
	case VolumeTypeImage:
		prefix = "i"
	default:
		prefix = "u"
	}

	// Remove hyphens from UUID for ONTAP size constraints (though ONTAP FlexVol supports 255 chars, it's cleaner)
	return fmt.Sprintf("%s-%s", prefix, vol.name)
}

// listFlexVols retrieves all FlexVols in the specified aggregate and SVM.
func (c *netappClient) listFlexVols(ctx context.Context, svmName string, aggrName string) ([]netappFlexVol, error) {
	var resp netappFlexVolResponse
	path := fmt.Sprintf("/storage/volumes?svm.name=%s&aggregates.name=%s&fields=uuid,name,svm", svmName, aggrName)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Failed listing FlexVols: %w", err)
	}

	return resp.Records, nil
}

type netappSnapshot struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type netappSnapshotResponse struct {
	Records []netappSnapshot `json:"records"`
}

// createSnapshot creates an ONTAP snapshot of a FlexVol.
func (c *netappClient) createSnapshot(ctx context.Context, volUUID string, name string) error {
	req := map[string]string{
		"name": name,
	}

	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/storage/volumes/%s/snapshots", volUUID), req, nil)
	if err != nil {
		return fmt.Errorf("Failed creating snapshot: %w", err)
	}

	return nil
}

// getSnapshot retrieves an ONTAP snapshot.
func (c *netappClient) getSnapshot(ctx context.Context, volUUID string, name string) (*netappSnapshot, error) {
	var resp netappSnapshotResponse
	path := fmt.Sprintf("/storage/volumes/%s/snapshots?name=%s&fields=uuid,name", volUUID, name)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Records) == 0 {
		return nil, fmt.Errorf("Snapshot %q not found", name)
	}

	return &resp.Records[0], nil
}

// listSnapshots returns every snapshot on the given FlexVol.
func (c *netappClient) listSnapshots(ctx context.Context, volUUID string) ([]netappSnapshot, error) {
	var resp netappSnapshotResponse
	path := fmt.Sprintf("/storage/volumes/%s/snapshots?fields=uuid,name", volUUID)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, err
	}

	return resp.Records, nil
}

// renameSnapshot renames an ONTAP snapshot in place.
func (c *netappClient) renameSnapshot(ctx context.Context, volUUID string, snapUUID string, newName string) error {
	req := map[string]string{"name": newName}
	err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/storage/volumes/%s/snapshots/%s", volUUID, snapUUID), req, nil)
	if err != nil {
		return fmt.Errorf("Failed renaming snapshot: %w", err)
	}

	return nil
}

// deleteSnapshot deletes an ONTAP snapshot.
func (c *netappClient) deleteSnapshot(ctx context.Context, volUUID string, snapUUID string) error {
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/storage/volumes/%s/snapshots/%s", volUUID, snapUUID), nil, nil)
	if err != nil {
		return fmt.Errorf("Failed deleting snapshot: %w", err)
	}

	return nil
}

// restoreSnapshot restores a FlexVol to an ONTAP snapshot.
func (c *netappClient) restoreSnapshot(ctx context.Context, volUUID string, snapUUID string) error {
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/storage/volumes/%s/snapshots/%s/actions/restore", volUUID, snapUUID), nil, nil)
	if err != nil {
		return fmt.Errorf("Failed restoring snapshot: %w", err)
	}

	return nil
}

// createFlexClone creates a new FlexVol cloned from an existing snapshot.
func (c *netappClient) createFlexClone(ctx context.Context, cloneName string, parentVolUUID string, parentSnapName string) error {
	req := map[string]interface{}{
		"name": cloneName,
		"clone": map[string]interface{}{
			"is_flexclone": true,
			"parent_volume": map[string]string{
				"uuid": parentVolUUID,
			},
			"parent_snapshot": map[string]string{
				"name": parentSnapName,
			},
		},
	}

	err := c.do(ctx, http.MethodPost, "/storage/volumes", req, nil)
	if err != nil {
		return fmt.Errorf("Failed creating FlexClone: %w", err)
	}

	return nil
}

type netappSubsystem struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	TargetNQN string `json:"target_nqn"`
}

type netappSubsystemResponse struct {
	Records []netappSubsystem `json:"records"`
}

type netappIPInterface struct {
	IP struct {
		Address string `json:"address"`
	} `json:"ip"`
}

type netappIPInterfaceResponse struct {
	Records []netappIPInterface `json:"records"`
}

// getFlexVol fetches a FlexVol by name.
func (c *netappClient) getFlexVol(ctx context.Context, name string, svmName string) (*netappFlexVol, error) {
	var resp netappFlexVolResponse
	path := fmt.Sprintf("/storage/volumes?name=%s&svm.name=%s&fields=uuid,name,svm", name, svmName)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Records) == 0 {
		return nil, fmt.Errorf("FlexVol %q not found", name)
	}

	return &resp.Records[0], nil
}

// getNamespace fetches a Namespace by path.
func (c *netappClient) getNamespace(ctx context.Context, path string, svmName string) (*netappNamespace, error) {
	var resp netappNamespaceResponse
	apiPath := fmt.Sprintf("/protocols/nvme/namespaces?name=%s&svm.name=%s&fields=uuid,name,nguid,space", path, svmName)

	err := c.do(ctx, http.MethodGet, apiPath, nil, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Records) == 0 {
		return nil, fmt.Errorf("Namespace %q not found", path)
	}

	return &resp.Records[0], nil
}

// getSubsystem fetches a Subsystem by name.
func (c *netappClient) getSubsystem(ctx context.Context, name string, svmName string) (*netappSubsystem, error) {
	var resp netappSubsystemResponse
	path := fmt.Sprintf("/protocols/nvme/subsystems?name=%s&svm.name=%s&fields=uuid,name,target_nqn", name, svmName)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, err
	}

	if len(resp.Records) == 0 {
		return nil, fmt.Errorf("Subsystem %q not found", name)
	}

	return &resp.Records[0], nil
}

// ensureSubsystem ensures an NVMe subsystem exists for a host, and creates it if it doesn't.
func (c *netappClient) ensureSubsystem(ctx context.Context, name string, svmName string, osType string) (*netappSubsystem, error) {
	subsys, err := c.getSubsystem(ctx, name, svmName)
	if err == nil {
		return subsys, nil
	}

	// Create if missing
	req := map[string]interface{}{
		"name": name,
		"svm": map[string]string{
			"name": svmName,
		},
		"os_type": osType,
	}

	err = c.do(ctx, http.MethodPost, "/protocols/nvme/subsystems", req, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed creating subsystem %q: %w", name, err)
	}

	return c.getSubsystem(ctx, name, svmName)
}

// addHostToSubsystem adds a host NQN to a subsystem.
func (c *netappClient) addHostToSubsystem(ctx context.Context, subsysUUID string, hostNQN string) error {
	req := map[string]interface{}{
		"records": []map[string]string{
			{"nqn": hostNQN},
		},
	}

	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/protocols/nvme/subsystems/%s/hosts", subsysUUID), req, nil)
	if err != nil {
		// Tolerate if the host is already in the subsystem
		if !api.StatusErrorCheck(err, http.StatusConflict) {
			return err
		}
	}

	return nil
}

// removeHostFromSubsystem removes a host NQN from a subsystem.
func (c *netappClient) removeHostFromSubsystem(ctx context.Context, subsysUUID string, hostNQN string) error {
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/protocols/nvme/subsystems/%s/hosts/%s", subsysUUID, hostNQN), nil, nil)
	if err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
		return err
	}

	return nil
}

// mapNamespace maps an NVMe namespace to an NVMe subsystem.
func (c *netappClient) mapNamespace(ctx context.Context, namespaceUUID string, subsysUUID string) error {
	req := map[string]interface{}{
		"namespace": map[string]string{
			"uuid": namespaceUUID,
		},
		"subsystem": map[string]string{
			"uuid": subsysUUID,
		},
	}

	err := c.do(ctx, http.MethodPost, "/protocols/nvme/subsystem-maps", req, nil)
	if err != nil {
		// Ignore if already mapped
		if !api.StatusErrorCheck(err, http.StatusConflict) {
			return fmt.Errorf("Failed mapping namespace: %w", err)
		}
	}

	return nil
}

// unmapNamespace unmaps an NVMe namespace from an NVMe subsystem.
func (c *netappClient) unmapNamespace(ctx context.Context, namespaceUUID string, subsysUUID string) error {
	err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/protocols/nvme/subsystem-maps/%s/%s", subsysUUID, namespaceUUID), nil, nil)
	if err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
		return fmt.Errorf("Failed unmapping namespace: %w", err)
	}

	return nil
}

// getNVMeTargetPortals returns all NVMe-capable data LIF IPs for the given SVM.
func (c *netappClient) getNVMeTargetPortals(ctx context.Context, svmName string) ([]string, error) {
	var resp netappIPInterfaceResponse
	path := fmt.Sprintf("/network/ip/interfaces?services=data_nvme_tcp&svm.name=%s&fields=ip.address", svmName)

	err := c.do(ctx, http.MethodGet, path, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("Failed getting NVMe target portals: %w", err)
	}

	var ips []string
	for _, rec := range resp.Records {
		if rec.IP.Address != "" {
			ips = append(ips, rec.IP.Address)
		}
	}

	return ips, nil
}
