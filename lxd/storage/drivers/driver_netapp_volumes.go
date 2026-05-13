package drivers

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/canonical/lxd/lxd/backup"
	"github.com/canonical/lxd/lxd/instancewriter"
	"github.com/canonical/lxd/lxd/migration"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/ioprogress"
	"github.com/canonical/lxd/shared/revert"
	"github.com/canonical/lxd/shared/units"
)

// CreateVolume creates a new volume.
func (d *netapp) CreateVolume(vol Volume, filler *VolumeFiller, progressReporter ioprogress.ProgressReporter) error {
	revert := revert.New()
	defer revert.Fail()

	err := d.createVolume(vol)
	if err != nil {
		return err
	}
	revert.Add(func() { _ = d.DeleteVolume(vol, progressReporter) })

	// VM blocks require a companion filesystem volume for metadata.
	if vol.IsVMBlock() {
		fsVol := vol.NewVMBlockFilesystemVolume()
		err = d.createVolume(fsVol)
		if err != nil {
			return err
		}
	}

	revert.Success()
	return nil
}

func (d *netapp) createVolume(vol Volume) error {
	volName := d.client().getVolumeName(vol)
	aggrName := d.config["netapp.aggregate"]
	svmName := d.client().svmName

	sizeStr := vol.ConfigSize()
	if sizeStr == "" {
		sizeStr = d.defaultBlockVolumeSize()
	}

	sizeBytes, err := units.ParseByteSizeString(sizeStr)
	if err != nil {
		return fmt.Errorf("Failed parsing volume size %q: %w", sizeStr, err)
	}

	// ONTAP namespaces must be a multiple of 4 KiB; the FlexVol can host the
	// namespace plus its own metadata so we keep the two sizes aligned.
	sizeBytes = d.roundVolumeBlockSizeBytes(vol, sizeBytes)

	err = d.client().createFlexVol(d.state.ShutdownCtx, volName, svmName, aggrName, sizeBytes)
	if err != nil {
		return fmt.Errorf("Failed creating FlexVol: %w", err)
	}

	err = d.client().createNamespace(d.state.ShutdownCtx, volName, "ns0", svmName, sizeBytes)
	if err != nil {
		return fmt.Errorf("Failed creating NVMe namespace: %w", err)
	}

	return nil
}

// GetVolumeDiskPath returns the local device path for a block-content volume.
// The caller must have MountVolume()'d the volume first.
func (d *netapp) GetVolumeDiskPath(vol Volume) (string, error) {
	if !IsContentBlock(vol.contentType) {
		return "", ErrNotSupported
	}

	return d.getMappedDevPath(d.client().getVolumeName(vol))
}

// HasVolume returns whether the FlexVol backing the volume currently exists on
// the appliance. 404 from getFlexVol is treated as "not found".
func (d *netapp) HasVolume(vol Volume) (bool, error) {
	volName := d.client().getVolumeName(vol)

	_, err := d.client().getFlexVol(d.state.ShutdownCtx, volName, d.client().svmName)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

// getMappedDevPath resolves the NVMe namespace for the given volume to a local
// device path. The namespace NGUID is what the Linux NVMe driver exposes via
// /dev/disk/by-id/nvme-eui.<nguid> once the host has an active session.
func (d *netapp) getMappedDevPath(volName string) (string, error) {
	svmName := d.client().svmName
	nsPath := fmt.Sprintf("/vol/%s/ns0", volName)

	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err != nil {
		return "", err
	}

	if ns.NGUID == "" {
		return "", fmt.Errorf("Namespace %q has no NGUID", nsPath)
	}

	conn, err := d.connector()
	if err != nil {
		return "", err
	}

	// The Linux NVMe driver uses the namespace NGUID as the eui identifier in
	// /dev/disk/by-id, lower-cased and without separators.
	suffix := strings.ToLower(ns.NGUID)
	filter := func(devPath string) bool {
		return strings.HasSuffix(devPath, suffix)
	}

	return conn.GetDiskDevicePath(filter)
}

// DeleteVolume deletes an existing volume.
func (d *netapp) DeleteVolume(vol Volume, progressReporter ioprogress.ProgressReporter) error {
	err := d.deleteVolume(vol)
	if err != nil {
		return err
	}

	if vol.IsVMBlock() {
		fsVol := vol.NewVMBlockFilesystemVolume()
		err = d.deleteVolume(fsVol)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *netapp) deleteVolume(vol Volume) error {
	volName := d.client().getVolumeName(vol)
	svmName := d.client().svmName
	nsPath := fmt.Sprintf("/vol/%s/ns0", volName)

	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err == nil {
		// Attempt to fetch subsystem UUID (e.g. subsystem name equivalent to LXD host NQN prefix)
		// and unmap namespace if we kept references, but usually deleting the namespace works immediately.
		// However, per API specs, we should unmap first just in case limits apply.
		subsysName := d.getSubsystemName()
		subsys, subErr := d.client().getSubsystem(d.state.ShutdownCtx, subsysName, svmName)
		if subErr == nil {
			_ = d.client().unmapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID)
		}

		err = d.client().deleteNamespace(d.state.ShutdownCtx, ns.UUID)
		if err != nil {
			return err
		}
	}

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, volName, svmName)
	if err == nil {
		err = d.client().deleteFlexVol(d.state.ShutdownCtx, flexVol.UUID)
		if err != nil {
			return err
		}
	}

	return nil
}

// getSubsystemName returns a safe subsystem name derived from the LXD Node configuration.
func (d *netapp) getSubsystemName() string {
	// Usually based on the cluster node name or the node's hostname
	return "lxd-" + d.state.ServerName
}

// ensureHost creates or returns the target NVMe subsystem structure mapped to the LXD Node host NQN.
func (d *netapp) ensureHost() (*netappSubsystem, error) {
	svmName := d.client().svmName
	subsysName := d.getSubsystemName()

	// Fetch LXD's deterministic NVMe NQN for this host via the connector. The
	// NQN must be stable across LXD restarts, which is why the connector
	// derives it from the server UUID rather than the hostname.
	conn, err := d.connector()
	if err != nil {
		return nil, err
	}

	hostNQN, err := conn.QualifiedName()
	if err != nil {
		return nil, fmt.Errorf("Failed getting host NQN: %w", err)
	}

	subsys, err := d.client().ensureSubsystem(d.state.ShutdownCtx, subsysName, svmName, "linux")
	if err != nil {
		return nil, err
	}

	err = d.client().addHostToSubsystem(d.state.ShutdownCtx, subsys.UUID, hostNQN)
	if err != nil {
		return nil, err
	}

	return subsys, nil
}

// CreateVolumeSnapshot creates a snapshot of a volume.
func (d *netapp) CreateVolumeSnapshot(snapVol Volume, progressReporter ioprogress.ProgressReporter) error {
	revert := revert.New()
	defer revert.Fail()

	err := d.createVolumeSnapshot(snapVol)
	if err != nil {
		return err
	}

	revert.Add(func() { _ = d.DeleteVolumeSnapshot(snapVol, progressReporter) })

	if snapVol.IsVMBlock() {
		fsVol := snapVol.NewVMBlockFilesystemVolume()
		err = d.createVolumeSnapshot(fsVol)
		if err != nil {
			return err
		}
	}

	revert.Success()
	return nil
}

func (d *netapp) createVolumeSnapshot(snapVol Volume) error {
	parentName := d.client().getVolumeName(snapVol.GetParent())
	svmName := d.client().svmName

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, parentName, svmName)
	if err != nil {
		return fmt.Errorf("Failed getting parent FlexVol: %w", err)
	}

	// snapVol.name is stored as "<parent>/<snap>" in LXD; the ONTAP snapshot
	// name is scoped to the parent FlexVol so only the short component is used.
	_, snapName, _ := api.GetParentAndSnapshotName(snapVol.name)

	err = d.client().createSnapshot(d.state.ShutdownCtx, flexVol.UUID, snapName)
	if err != nil {
		return err
	}

	return nil
}

// DeleteVolumeSnapshot deletes a preset snapshot.
func (d *netapp) DeleteVolumeSnapshot(snapVol Volume, progressReporter ioprogress.ProgressReporter) error {
	err := d.deleteVolumeSnapshot(snapVol)
	if err != nil {
		return err
	}

	if snapVol.IsVMBlock() {
		fsVol := snapVol.NewVMBlockFilesystemVolume()
		err = d.deleteVolumeSnapshot(fsVol)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *netapp) deleteVolumeSnapshot(snapVol Volume) error {
	parentName := d.client().getVolumeName(snapVol.GetParent())
	svmName := d.client().svmName
	_, snapName, _ := api.GetParentAndSnapshotName(snapVol.name)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, parentName, svmName)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}

		return err
	}

	snap, err := d.client().getSnapshot(d.state.ShutdownCtx, flexVol.UUID, snapName)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil
		}

		return err
	}

	// Tear down any temporary read-write clone created from this snapshot
	// before the snapshot itself: ONTAP refuses to delete a snapshot that
	// still has dependent FlexClones.
	tmpCloneName := "s-" + snapName
	cloneVol, err := d.client().getFlexVol(d.state.ShutdownCtx, tmpCloneName, svmName)
	if err == nil {
		_ = d.client().deleteFlexVol(d.state.ShutdownCtx, cloneVol.UUID)
	}

	err = d.client().deleteSnapshot(d.state.ShutdownCtx, flexVol.UUID, snap.UUID)
	if err != nil && !api.StatusErrorCheck(err, http.StatusNotFound) {
		return err
	}

	return nil
}

// MountVolumeSnapshot sets up a read-only mount on top of a snapshot.
func (d *netapp) MountVolumeSnapshot(snapVol Volume, progressReporter ioprogress.ProgressReporter) error {
	revert := revert.New()
	defer revert.Fail()

	parentName := d.client().getVolumeName(snapVol.GetParent())
	svmName := d.client().svmName
	_, snapName, _ := api.GetParentAndSnapshotName(snapVol.name)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, parentName, svmName)
	if err != nil {
		return fmt.Errorf("Failed getting parent FlexVol for snapshot clone: %w", err)
	}

	tmpCloneName := "s-" + snapName

	// FlexClone the snapshot into a temporary writable FlexVol so the host can
	// map it like any other namespace; ONTAP snapshots themselves are read-only.
	err = d.client().createFlexClone(d.state.ShutdownCtx, tmpCloneName, flexVol.UUID, snapName)
	if err != nil {
		return fmt.Errorf("Failed creating temporary clone from snapshot: %w", err)
	}

	revert.Add(func() {
		clone, err := d.client().getFlexVol(d.state.ShutdownCtx, tmpCloneName, svmName)
		if err == nil {
			_ = d.client().deleteFlexVol(d.state.ShutdownCtx, clone.UUID)
		}
	})

	// To mount it to the host, we fetch the NVMe namespace located within this new temporary clone and attach it.
	nsPath := fmt.Sprintf("/vol/%s/ns0", tmpCloneName)
	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err != nil {
		return fmt.Errorf("Failed retrieving namespace for snapshot clone mount: %w", err)
	}

	subsys, err := d.ensureHost()
	if err != nil {
		return fmt.Errorf("Failed ensuring host subsystem for snapshot mapping: %w", err)
	}

	err = d.client().mapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID)
	if err != nil {
		return fmt.Errorf("Failed mapping snapshot namespace to subsystem: %w", err)
	}
	revert.Add(func() { _ = d.client().unmapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID) })

	// Open the NVMe/TCP session and wait for the temp-clone namespace to
	// surface as a local block device. Mirrors MountVolume's tail.
	conn, err := d.connector()
	if err != nil {
		return err
	}

	var targets []string
	if targetConf := d.config["netapp.target"]; targetConf != "" {
		targets = append(targets, targetConf)
	} else {
		targets, err = d.client().getNVMeTargetPortals(d.state.ShutdownCtx, svmName)
		if err != nil {
			return fmt.Errorf("Failed obtaining NVMe target portals: %w", err)
		}
	}

	disconnect, err := conn.Connect(d.state.ShutdownCtx, subsys.TargetNQN, targets...)
	if err != nil {
		return fmt.Errorf("Failed connecting to NVMe subsystem: %w", err)
	}

	revert.Add(disconnect)

	if ns.NGUID == "" {
		return fmt.Errorf("Snapshot namespace %q has no NGUID", nsPath)
	}

	suffix := strings.ToLower(ns.NGUID)
	filter := func(devPath string) bool {
		return strings.HasSuffix(devPath, suffix)
	}

	_, err = conn.WaitDiskDevicePath(d.state.ShutdownCtx, filter)
	if err != nil {
		return fmt.Errorf("Failed waiting for snapshot NVMe device: %w", err)
	}

	revert.Success()
	return nil
}

// UnmountVolumeSnapshot tears down a volume snapshot mount.
func (d *netapp) UnmountVolumeSnapshot(snapVol Volume, progressReporter ioprogress.ProgressReporter) (bool, error) {
	svmName := d.client().svmName
	tmpCloneName := "s-" + snapVol.name
	nsPath := fmt.Sprintf("/vol/%s/ns0", tmpCloneName)

	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err == nil {
		subsysName := d.getSubsystemName()
		subsys, subErr := d.client().getSubsystem(d.state.ShutdownCtx, subsysName, svmName)
		if subErr == nil {
			_ = d.client().unmapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID)
			// Trigger disconnect if last connection...
		}
	}

	clone, err := d.client().getFlexVol(d.state.ShutdownCtx, tmpCloneName, svmName)
	if err == nil {
		_ = d.client().deleteFlexVol(d.state.ShutdownCtx, clone.UUID)
	}

	return true, nil
}

// RestoreVolume restores a volume to a snapshot.
func (d *netapp) RestoreVolume(vol Volume, snapVol Volume, progressReporter ioprogress.ProgressReporter) error {
	parentName := d.client().getVolumeName(vol)
	svmName := d.client().svmName

	// LXD stores snapshot volumes under the "<parent>/<snap>" name, but the
	// ONTAP snapshot itself is scoped to the parent FlexVol and only carries
	// the short snapshot name.
	_, snapName, _ := api.GetParentAndSnapshotName(snapVol.name)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, parentName, svmName)
	if err != nil {
		return fmt.Errorf("Failed getting parent FlexVol to restore: %w", err)
	}

	snap, err := d.client().getSnapshot(d.state.ShutdownCtx, flexVol.UUID, snapName)
	if err != nil {
		return fmt.Errorf("Failed getting snapshot for restore: %w", err)
	}

	err = d.client().restoreSnapshot(d.state.ShutdownCtx, flexVol.UUID, snap.UUID)
	if err != nil {
		return err
	}

	if vol.IsVMBlock() {
		fsVol := vol.NewVMBlockFilesystemVolume()
		fsParentName := d.client().getVolumeName(fsVol)

		fsFlexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, fsParentName, svmName)
		if err != nil {
			return fmt.Errorf("Failed getting generic FlexVol to restore: %w", err)
		}

		fsSnap, err := d.client().getSnapshot(d.state.ShutdownCtx, fsFlexVol.UUID, snapName)
		if err != nil {
			return fmt.Errorf("Failed getting filesystem snapshot for restore: %w", err)
		}

		err = d.client().restoreSnapshot(d.state.ShutdownCtx, fsFlexVol.UUID, fsSnap.UUID)
		if err != nil {
			return err
		}
	}

	return nil
}

// MountVolume maps the namespace to the host's NVMe subsystem, opens the TCP
// session if needed, and waits for the resulting block device to appear.
func (d *netapp) MountVolume(vol Volume, progressReporter ioprogress.ProgressReporter) error {
	revert := revert.New()
	defer revert.Fail()

	svmName := d.client().svmName
	volName := d.client().getVolumeName(vol)
	nsPath := fmt.Sprintf("/vol/%s/ns0", volName)

	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err != nil {
		return fmt.Errorf("Failed retrieving namespace for mount: %w", err)
	}

	subsys, err := d.ensureHost()
	if err != nil {
		return fmt.Errorf("Failed ensuring host subsystem: %w", err)
	}

	err = d.client().mapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID)
	if err != nil {
		return fmt.Errorf("Failed mapping namespace to subsystem: %w", err)
	}

	revert.Add(func() { _ = d.client().unmapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID) })

	// Connect NVMe Subsystem
	targets := []string{}
	// Fallback to configured targets instead if defined.
	if targetConf := d.config["netapp.target"]; targetConf != "" {
		targets = append(targets, targetConf)
	} else {
		targets, err = d.client().getNVMeTargetPortals(d.state.ShutdownCtx, svmName)
		if err != nil {
			return fmt.Errorf("Failed obtaining NVMe target portals: %w", err)
		}
	}

	conn, err := d.connector()
	if err != nil {
		return err
	}

	disconnect, err := conn.Connect(d.state.ShutdownCtx, subsys.TargetNQN, targets...)
	if err != nil {
		return fmt.Errorf("Failed to connect to NVMe subsystem: %w", err)
	}

	revert.Add(disconnect)

	// Wait for the kernel to expose the namespace as a /dev/disk/by-id entry
	// keyed by the namespace's NGUID. Without this wait, immediately consuming
	// the device (mkfs, MountTask) races the udev settle.
	if ns.NGUID == "" {
		return fmt.Errorf("Namespace %q has no NGUID", nsPath)
	}

	suffix := strings.ToLower(ns.NGUID)
	filter := func(devPath string) bool {
		return strings.HasSuffix(devPath, suffix)
	}

	_, err = conn.WaitDiskDevicePath(d.state.ShutdownCtx, filter)
	if err != nil {
		return fmt.Errorf("Failed waiting for NVMe device: %w", err)
	}

	revert.Success()
	return nil
}

// UnmountVolume unmounts the volume.
func (d *netapp) UnmountVolume(vol Volume, keepBlockDev bool, progressReporter ioprogress.ProgressReporter) (bool, error) {
	volName := d.client().getVolumeName(vol)
	svmName := d.client().svmName
	nsPath := fmt.Sprintf("/vol/%s/ns0", volName)

	// Assume we unmounted filesystem using common unmount routines...
	// Then we disconnect block storage mappings:

	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err != nil {
		// Log missing namespaces as non-fatal but exit to prevent dangling
		return false, nil
	}

	subsysName := d.getSubsystemName()
	subsys, err := d.client().getSubsystem(d.state.ShutdownCtx, subsysName, svmName)
	if err != nil {
		return false, nil
	}

	err = d.client().unmapNamespace(d.state.ShutdownCtx, ns.UUID, subsys.UUID)
	if err != nil {
		return false, fmt.Errorf("Failed to unmap NVMe volume: %w", err)
	}

	// Disconnect NVMe target sessions.
	conn, err := d.connector()
	if err != nil {
		return false, err
	}

	err = conn.Disconnect(subsys.TargetNQN)
	if err != nil {
		return false, fmt.Errorf("Failed to disconnect NVMe session: %w", err)
	}

	return true, nil
}

// SetVolumeQuota sets the quota on the volume.
func (d *netapp) SetVolumeQuota(vol Volume, size string, allowUnsafeResize bool, progressReporter ioprogress.ProgressReporter) error {
	svmName := d.client().svmName
	volName := d.client().getVolumeName(vol)

	sizeBytes, err := units.ParseByteSizeString(size)
	if err != nil {
		return fmt.Errorf("Failed calculating volume size: %w", err)
	}

	// ONTAP namespaces must be a multiple of 4 KiB. Round up rather than
	// rejecting so callers can pass human-friendly sizes like "10GiB" without
	// worrying about alignment.
	sizeBytes = d.roundVolumeBlockSizeBytes(vol, sizeBytes)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, volName, svmName)
	if err != nil {
		return fmt.Errorf("Failed retrieving parent FlexVol for resize: %w", err)
	}

	nsPath := fmt.Sprintf("/vol/%s/ns0", volName)
	ns, err := d.client().getNamespace(d.state.ShutdownCtx, nsPath, svmName)
	if err != nil {
		return fmt.Errorf("Failed retrieving NVMe namespace for resize: %w", err)
	}

	// Shrinking a block volume risks corrupting on-disk data unless the caller
	// has stopped the consumer; allowUnsafeResize is the explicit opt-in.
	if sizeBytes < ns.Space.Size && IsContentBlock(vol.contentType) && !allowUnsafeResize {
		return ErrCannotBeShrunk
	}

	if sizeBytes > ns.Space.Size {
		err = d.client().resizeFlexVol(d.state.ShutdownCtx, flexVol.UUID, sizeBytes)
		if err != nil {
			return err
		}
	}

	err = d.client().resizeNamespace(d.state.ShutdownCtx, ns.UUID, sizeBytes)
	if err != nil {
		return err
	}

	// Shrink the flexvol safely last if reducing quota
	if sizeBytes < ns.Space.Size {
		err = d.client().resizeFlexVol(d.state.ShutdownCtx, flexVol.UUID, sizeBytes)
		if err != nil && !api.StatusErrorCheck(err, http.StatusConflict) {
			return err
		}
	}

	// Wait for the local NVMe block device to reflect the new size. This is
	// best-effort: the volume may not currently be mapped to this host.
	devicePath, err := d.getMappedDevPath(volName)
	if err == nil && devicePath != "" {
		conn, err := d.connector()
		if err != nil {
			return err
		}

		_ = conn.WaitDiskDeviceResize(d.state.ShutdownCtx, devicePath, sizeBytes)
	}

	return nil
}

// RenameVolume renames a volume and its snapshots.
func (d *netapp) RenameVolume(vol Volume, newName string, progressReporter ioprogress.ProgressReporter) error {
	return ErrNotSupported
}

// VolumeSnapshots returns the short names of all ONTAP snapshots taken on the
// FlexVol that backs the given LXD volume.
func (d *netapp) VolumeSnapshots(vol Volume) ([]string, error) {
	volName := d.client().getVolumeName(vol)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, volName, d.client().svmName)
	if err != nil {
		if api.StatusErrorCheck(err, http.StatusNotFound) {
			return nil, nil
		}

		return nil, err
	}

	snaps, err := d.client().listSnapshots(d.state.ShutdownCtx, flexVol.UUID)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(snaps))
	for _, s := range snaps {
		names = append(names, s.Name)
	}

	return names, nil
}

// RenameVolumeSnapshot renames an ONTAP snapshot in place.
func (d *netapp) RenameVolumeSnapshot(snapVol Volume, newSnapshotName string, progressReporter ioprogress.ProgressReporter) error {
	parentName := d.client().getVolumeName(snapVol.GetParent())
	_, oldShort, _ := api.GetParentAndSnapshotName(snapVol.name)

	flexVol, err := d.client().getFlexVol(d.state.ShutdownCtx, parentName, d.client().svmName)
	if err != nil {
		return err
	}

	snap, err := d.client().getSnapshot(d.state.ShutdownCtx, flexVol.UUID, oldShort)
	if err != nil {
		return err
	}

	return d.client().renameSnapshot(d.state.ShutdownCtx, flexVol.UUID, snap.UUID, newSnapshotName)
}

// CheckVolumeSnapshots verifies that the expected set of LXD snapshots matches
// what exists on the appliance. ONTAP names them flat per FlexVol, so the
// comparison is a simple set match on the short snapshot names.
func (d *netapp) CheckVolumeSnapshots(vol Volume, snapVols []Volume) error {
	existing, err := d.VolumeSnapshots(vol)
	if err != nil {
		return err
	}

	have := make(map[string]struct{}, len(existing))
	for _, n := range existing {
		have[n] = struct{}{}
	}

	for _, sv := range snapVols {
		_, short, _ := api.GetParentAndSnapshotName(sv.name)
		_, ok := have[short]
		if !ok {
			return fmt.Errorf("Snapshot %q is missing on the storage backend", sv.name)
		}
	}

	return nil
}

// BackupVolume streams volume to a backup.
func (d *netapp) BackupVolume(vol VolumeCopy, projectName string, tarWriter *instancewriter.InstanceTarWriter, optimized bool, snapshots []string, progressReporter ioprogress.ProgressReporter) error {
	return genericVFSBackupVolume(d, vol, tarWriter, snapshots, progressReporter)
}

// CreateVolumeFromBackup re-creates a volume from its exported state.
func (d *netapp) CreateVolumeFromBackup(vol VolumeCopy, srcBackup backup.Info, srcData io.ReadSeeker, progressReporter ioprogress.ProgressReporter) (VolumePostHook, revert.Hook, error) {
	return genericVFSBackupUnpack(d, d.state, vol, srcBackup.Snapshots, srcData, progressReporter)
}

// CreateVolumeFromCopy creates a new volume from a copy of an existing volume.
// The optimised FlexClone path is not yet implemented; callers fall back to the
// generic BLOCK_AND_RSYNC migration declared by MigrationTypes.
func (d *netapp) CreateVolumeFromCopy(vol VolumeCopy, srcVol VolumeCopy, allowInconsistent bool, progressReporter ioprogress.ProgressReporter) error {
	return ErrNotSupported
}

// MigrateVolume sends a volume to the target host via the generic transport.
func (d *netapp) MigrateVolume(vol VolumeCopy, conn io.ReadWriteCloser, volSrcArgs *migration.VolumeSourceArgs, progressReporter ioprogress.ProgressReporter) error {
	return genericVFSMigrateVolume(d, d.state, vol, conn, volSrcArgs, progressReporter)
}

// CreateVolumeFromMigration creates a volume being received from another LXD.
func (d *netapp) CreateVolumeFromMigration(vol VolumeCopy, conn io.ReadWriteCloser, volTargetArgs migration.VolumeTargetArgs, preFiller *VolumeFiller, progressReporter ioprogress.ProgressReporter) error {
	if volTargetArgs.ClusterMoveSourceName != "" {
		err := vol.EnsureMountPath()
		if err != nil {
			return err
		}

		if vol.IsVMBlock() {
			fsVol := NewVolumeCopy(vol.NewVMBlockFilesystemVolume())
			err = d.CreateVolumeFromMigration(fsVol, conn, volTargetArgs, preFiller, progressReporter)
			if err != nil {
				return err
			}
		}

		return nil
	}

	_, err := genericVFSCreateVolumeFromMigration(d, nil, vol, conn, volTargetArgs, preFiller, progressReporter)
	return err
}

// EnsureImage materialises the cached image volume on disk if it is not already
// present. The same-pool optimised copy path will then FlexClone this volume.
func (d *netapp) EnsureImage(imgVol Volume, filler *VolumeFiller, progressReporter ioprogress.ProgressReporter) error {
	return ensureImageVolume(imgVol, filler, progressReporter)
}

// RefreshVolume updates an existing volume to match the state of another volume.
func (d *netapp) RefreshVolume(vol VolumeCopy, srcVol VolumeCopy, refreshSnapshots []string, allowInconsistent bool, progressReporter ioprogress.ProgressReporter) error {
	return ErrNotSupported
}

// ListVolumes returns a list of LXD volumes in the storage pool.
func (d *netapp) ListVolumes() ([]Volume, error) {
	aggrName := d.config["netapp.aggregate"]
	svmName := d.client().svmName

	flexVols, err := d.client().listFlexVols(d.state.ShutdownCtx, svmName, aggrName)
	if err != nil {
		return nil, err
	}

	volList := make([]Volume, 0, len(flexVols))

	for _, fv := range flexVols {
		var volType VolumeType
		var volName string

		parts := strings.Split(fv.Name, "-")
		if len(parts) < 2 || len(parts) > 3 {
			continue
		}

		prefix := parts[0]
		uuidPart := parts[1]

		switch prefix {
		case "c":
			volType = VolumeTypeContainer
		case "v":
			volType = VolumeTypeVM
		case "i":
			volType = VolumeTypeImage
		case "u":
			volType = VolumeTypeCustom
		default:
			// Foreign FlexVols and `s-` temp snapshot clones are ignored.
			continue
		}

		// LXD encodes the UUID with hyphens stripped, giving 32 hex chars.
		// Skip anything that doesn't match so we never surface admin-named
		// FlexVols that happen to share a leading letter.
		if !isOntapUUIDHex(uuidPart) {
			continue
		}

		volName = uuidPart
		contentType := ContentTypeFS

		if len(parts) == 3 {
			switch parts[2] {
			case "b":
				contentType = ContentTypeBlock
			case "i":
				contentType = ContentTypeISO
			default:
				continue
			}
		} else if volType == VolumeTypeVM {
			contentType = ContentTypeBlock
		}

		volList = append(volList, NewVolume(d, d.name, volType, contentType, volName, make(map[string]string), d.config))
	}

	return volList, nil
}
