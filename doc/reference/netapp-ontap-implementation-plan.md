# NetApp ONTAP Storage Driver — Implementation Plan

## Summary

This plan outlines the phased implementation of the `ontap` remote storage driver for LXD, based on the NetApp ONTAP REST API (9.16+) and using **NVMe/TCP** as the transport layer. The driver maps ONTAP NVMe namespaces as block devices on LXD hosts through the existing NVMe connector infrastructure.

---

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Transport | NVMe/TCP only | Preferred for new remote drivers per architecture guide; connector already mature |
| Pool mapping | Aggregate | Aggregate provides capacity boundary; owning SVM is auto-discovered |
| Namespace isolation | One FlexVol per namespace | Enables per-volume snapshot isolation and simplifies resize |
| Volume naming | UUID-based (`UUIDVolumeNames: true`) | ONTAP name length limits (255 chars), consistent with Pure/PowerFlex/PowerStore |
| API client | In-driver (like Pure), not `clients/` | Simpler dependency; Pure pattern works well for single-vendor API |
| Async operations | Job polling with `return_timeout` | ONTAP REST returns 202 + job for ops > 2s; use `return_timeout=30` to attempt synchronous completion |
| Snapshots | FlexVol-level snapshot copies | Near-zero cost; one-to-one mapping with LXD snapshot concept |
| Image optimization | FlexClone | Metadata-only writable copy — near-instant instance creation from images |
| Snapshot mount | Temporary FlexClone from snapshot (like PowerStore) | ONTAP snapshots are read-only; need a writable clone for host-mapped access |

---

## Phase 0: Scaffolding and Registration

**Goal:** Create the driver skeleton that compiles and registers with the loader.

### Files to create

| File | Purpose |
|------|---------|
| `lxd/storage/drivers/driver_ontap.go` | Pool lifecycle: struct, `load()`, `Info()`, `FillConfig()`, `Validate()`, `ValidateSource()`, `SourceIdentifier()`, `Create()`, `Delete()`, `Mount()`, `Unmount()`, `GetResources()`, `Update()`, `MigrationTypes()` |
| `lxd/storage/drivers/driver_ontap_volumes.go` | Volume lifecycle: `CreateVolume()`, `DeleteVolume()`, `MountVolume()`, `UnmountVolume()`, snapshots, copy, refresh, migration, backup stubs |
| `lxd/storage/drivers/driver_ontap_util.go` | REST client (`ontapClient`), host/subsystem helpers, volume naming, job polling |

### Files to modify

| File | Change |
|------|--------|
| `lxd/storage/drivers/load.go` | Add `"ontap": func() driver { return &ontap{} }` to the `drivers` map |

### Driver struct (initial)

```go
type ontap struct {
    common

    storageConnector connectors.Connector
    httpClient       *ontapClient
}
```

### Info return

```go
Info{
    Name:                         "ontap",
    Version:                      ontapVersion,
    DefaultBlockSize:             d.defaultBlockVolumeSize(),
    DefaultVMBlockFilesystemSize: d.defaultVMBlockFilesystemSize(),
    OptimizedImages:              true,
    PreservesInodes:              false,
    Remote:                       true,
    VolumeTypes:                  []VolumeType{VolumeTypeCustom, VolumeTypeVM, VolumeTypeContainer, VolumeTypeImage},
    BlockBacking:                 true,
    RunningCopyFreeze:            true,
    DirectIO:                     true,
    IOUring:                      true,
    MountedRoot:                  false,
    PopulateParentVolumeUUID:     true,
    UUIDVolumeNames:              true,
}
```

### Configuration keys

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `netapp.gateway` | string | yes | — | ONTAP cluster management endpoint (e.g., `https://mgmt.ontap.local`) |
| `netapp.gateway.verify` | bool | no | `true` | Verify TLS certificate of the gateway |
| `netapp.user.name` | string | yes | — | REST API username with appropriate RBAC role |
| `netapp.user.password` | string | yes | — | REST API password |
| `netapp.aggregate` | string | yes | — | Storage aggregate (local tier) for FlexVol placement; the owning SVM is auto-discovered from the aggregate |
| `netapp.mode` | string | no | `nvme` | Transport mode (only `nvme` supported) |
| `netapp.target` | string | no | — | Comma-separated NVMe target addresses; if empty, LXD queries the ONTAP appliance for NVMe-capable data LIFs |
| `netapp.thin` | bool | no | `true` | Enable thin provisioning (disable namespace space reservation) |
| `volume.size` | string | no | `10GiB` | Default volume size (must be a multiple of 4KiB per ONTAP namespace alignment) |

### Supported connector

```go
var ontapSupportedConnectors = []string{
    connectors.TypeNVME,
}
```

### SourceIdentifier

Implemented identically to Pure Storage and PowerStore — gateway address plus pool name:

```go
func (d *ontap) SourceIdentifier() (string, error) {
    if d.config["netapp.gateway"] == "" {
        return "", errors.New("Cannot derive identifier from empty gateway address")
    }

    if d.name == "" {
        return "", errors.New("Cannot derive identifier from empty pool name")
    }

    return d.config["netapp.gateway"] + "-" + d.name, nil
}
```

### Validate() requirements

- `netapp.mode` cannot be changed after pool creation (same guard as Pure Storage):

  ```go
  if d.config["netapp.mode"] != "" && d.config["netapp.mode"] != config["netapp.mode"] {
      return errors.New("NetApp ONTAP mode cannot be changed")
  }
  ```

- `volume.size` must use `validate.IsMultipleOfUnit("4KiB")` — ONTAP namespace size must be a multiple of 4096 bytes.

---

## Phase 1: REST API Client (`driver_ontap_util.go`)

**Goal:** Implement the ONTAP REST client capable of performing all required storage operations.

### Client design

```go
type ontapClient struct {
    gateway    string
    username   string
    password   string
    svmName    string
    aggregate  string
    skipVerify bool
    httpClient *http.Client
}
```

### Core API operations to implement

| Category | Method | ONTAP Endpoint | HTTP |
|----------|--------|----------------|------|
| **Job** | `waitForJob(jobUUID)` | `GET /api/cluster/jobs/{uuid}` | GET |
| **Aggregate** | `getAggregate(name)` | `GET /api/storage/aggregates?name=<aggr>&fields=uuid,space,home_node,snapmirror_label` | GET |
| **FlexVol** | `createFlexVol(name, svmName, aggrName, size)` | `POST /api/storage/volumes` | POST |
| **FlexVol** | `deleteFlexVol(uuid)` | `DELETE /api/storage/volumes/{uuid}` | DELETE |
| **FlexVol** | `resizeFlexVol(uuid, newSize)` | `PATCH /api/storage/volumes/{uuid}` | PATCH |
| **FlexVol** | `getFlexVol(name)` | `GET /api/storage/volumes?name=<n>&fields=uuid,name,svm` | GET |
| **Snapshot** | `createSnapshot(volUUID, name)` | `POST /api/storage/volumes/{uuid}/snapshots` | POST |
| **Snapshot** | `deleteSnapshot(volUUID, snapUUID)` | `DELETE /api/storage/volumes/{uuid}/snapshots/{snap_uuid}` | DELETE |
| **Snapshot** | `listSnapshots(volUUID)` | `GET /api/storage/volumes/{uuid}/snapshots` | GET |
| **Snapshot** | `restoreSnapshot(volUUID, snapUUID)` | `POST /api/storage/volumes/{uuid}/snapshots/{snap_uuid}/actions/restore` | POST |
| **Clone** | `createFlexClone(name, parentVolUUID, parentSnapName)` | `POST /api/storage/volumes` (with `clone` property) | POST |
| **Clone** | `splitClone(uuid)` | `PATCH /api/storage/volumes/{uuid}` (`clone.split_initiated=true`) | PATCH |
| **NVMe Service** | `getNVMeService(svmName)` | `GET /api/protocols/nvme/services?svm.name=<svm>` | GET |
| **NVMe Subsystem** | `ensureSubsystem(name, svmName, osType)` | `GET` then `POST /api/protocols/nvme/subsystems` | GET/POST |
| **NVMe Subsystem** | `getSubsystem(name, svmName)` | `GET /api/protocols/nvme/subsystems?name=<n>&svm.name=<svm>&fields=uuid,name,target_nqn` | GET |
| **NVMe Subsystem** | `deleteSubsystem(uuid)` | `DELETE /api/protocols/nvme/subsystems/{uuid}` | DELETE |
| **NVMe Subsystem** | `addHostToSubsystem(subsysUUID, hostNQN)` | `POST /api/protocols/nvme/subsystems/{uuid}/hosts` | POST |
| **NVMe Subsystem** | `removeHostFromSubsystem(subsysUUID, hostNQN)` | `DELETE /api/protocols/nvme/subsystems/{uuid}/hosts/{nqn}` | DELETE |
| **NVMe Namespace** | `createNamespace(flexvolName, namespaceName, svmName, size)` | `POST /api/protocols/nvme/namespaces` | POST |
| **NVMe Namespace** | `deleteNamespace(uuid)` | `DELETE /api/protocols/nvme/namespaces/{uuid}` | DELETE |
| **NVMe Namespace** | `resizeNamespace(uuid, newSize)` | `PATCH /api/protocols/nvme/namespaces/{uuid}` | PATCH |
| **NVMe Namespace** | `getNamespace(path)` | `GET /api/protocols/nvme/namespaces?name=<path>&svm.name=<svm>&fields=uuid,name,space` | GET |
| **NVMe Namespace** | `listNamespaces(svmName, flexvolName)` | `GET /api/protocols/nvme/namespaces?svm.name=<svm>&location.volume.name=<vol>` | GET |
| **NVMe Namespace Map** | `mapNamespace(namespaceUUID, subsysUUID)` | `POST /api/protocols/nvme/subsystem-maps` | POST |
| **NVMe Namespace Map** | `unmapNamespace(namespaceUUID, subsysUUID)` | `DELETE /api/protocols/nvme/subsystem-maps/{subsystem.uuid}/{namespace.uuid}` | DELETE |
| **NVMe Targets** | `getNVMeTargetPortals(svmName)` | `GET /api/network/ip/interfaces?services=data_nvme_tcp&svm.name=<svm>&fields=ip.address` | GET |
| **Resources** | `getAggregateSpace(uuid)` | `GET /api/storage/aggregates/{uuid}?fields=space` | GET |

### Job polling pattern

```go
func (c *ontapClient) waitForJob(ctx context.Context, jobUUID string) error {
    for {
        job, err := c.getJob(ctx, jobUUID)
        if err != nil {
            return err
        }
        switch job.State {
        case "success":
            return nil
        case "failure":
            return fmt.Errorf("Job %s failed: %s", jobUUID, job.Message)
        }
        // Wait before next poll (use exponential backoff or fixed interval).
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(2 * time.Second):
        }
    }
}
```

### HTTP request helper

- Use `return_timeout=30` on POST/PATCH/DELETE to attempt synchronous completion.
- If response is 202, extract `job.uuid` and call `waitForJob()`.
- Handle 409 (conflict/already exists) gracefully for idempotent operations (e.g., subsystem creation).
- Use HTTP Basic Auth (`Authorization: Basic base64(user:pass)`).

---

## Phase 2: Pool Lifecycle

**Goal:** Pool create, delete, mount, unmount, validate, and resources.

### Create flow

1. Call `getAggregate()` to validate the aggregate exists and has sufficient capacity; extract the owning SVM name/UUID from the response and store in volatile config (`volatile.svm.name`, `volatile.svm.uuid`).
2. Verify NVMe service is enabled on the discovered SVM via `getNVMeService()`.
3. No remote pool object is created (aggregate pre-exists externally, same as PowerFlex/PowerStore).

### Delete flow

1. Verify no remaining volumes belong to this pool.
2. Wipe local pool mount directory (`wipeDirectory(GetPoolMountPath(d.name))`).

### Mount/Unmount

No-op (same as Pure, PowerStore).

### GetResources

Query aggregate space: `GET /api/storage/aggregates/{uuid}?fields=space`.

---

## Phase 3: Volume Lifecycle (Basic)

**Goal:** Create, delete, mount, unmount single volumes.

### Volume naming strategy

Volume names follow the Pure Storage naming convention (hyphen-separated, UUID-based). Pool scoping is achieved by querying the pool's dedicated aggregate — no pool-name prefix is embedded in the volume name.

```
FlexVol:    <typePrefix>-<uuidNoHyphens>[-<contentSuffix>]
Namespace:  /vol/<flexvol_name>/ns0
```

Type prefixes (same as Pure/PowerStore):
- Container: `c`
- VM: `v`
- Image: `i`
- Custom: `u`

Content type suffixes (appended with hyphen separator):
- Block: `b`
- ISO: `i`
- Filesystem: (no suffix — default)

Snapshot clone prefix: `s` (prepended before type prefix, as in Pure).

Examples:
- Container filesystem: `c-550e8400e29b41d4a716446655440000`
- VM block volume: `v-550e8400e29b41d4a716446655440000-b`
- Image block volume: `i-550e8400e29b41d4a716446655440000-b`

### CreateVolume

1. Generate FlexVol name from volume UUID using Pure-style naming.
2. Create FlexVol with size + thin provisioning settings (guarantee=`none`, fractional_reserve=0).
3. Create NVMe namespace inside FlexVol at path `/vol/<flexvol>/ns0`, `os_type=linux`, space reservation disabled.
4. For `ContentTypeFS`: map namespace to subsystem, format with filesystem, unmap.
5. For VM block: also create companion filesystem volume.
6. Revert on any failure.

### DeleteVolume

1. Unmap namespace from subsystem (if mapped) via `unmapNamespace()`.
2. Delete NVMe namespace.
3. Delete FlexVol.
4. For VM block: also delete companion filesystem volume.
5. Treat 404 as non-fatal (idempotent delete).

### MountVolume (host mapping)

1. `ensureSubsystem()` — ensure an NVMe subsystem for this LXD host NQN exists on the SVM; add the host NQN via `addHostToSubsystem()` if not already present.
2. `mapVolume()` — map the NVMe namespace to the subsystem via `mapNamespace()`.
3. `getNVMeTargetPortals()` — query ONTAP for NVMe-capable data LIF addresses; use `netapp.target` if explicitly configured.
4. `connector.Connect()` — establish NVMe/TCP session to all target addresses using the subsystem's target NQN.
5. `getMappedDevPath()` — resolve `/dev/disk/by-id/nvme-eui.<EUI>` using the namespace NGUID.
6. Mount filesystem on block device (for filesystem content type volumes).

### UnmountVolume

1. Unmount filesystem.
2. `connector.RemoveDiskDevice()` — remove local block device.
3. `unmapVolume()` — remove namespace-to-subsystem mapping via `unmapNamespace()`.
4. `connector.Disconnect()` — close NVMe/TCP session if no other volumes remain.

---

## Phase 4: Snapshots

**Goal:** Create, delete, list, restore snapshots.

### CreateVolumeSnapshot

1. Create ONTAP snapshot on the namespace's FlexVol: `POST /api/storage/volumes/{uuid}/snapshots`.
2. For VM block: also snapshot companion volume.

### DeleteVolumeSnapshot

1. Delete ONTAP snapshot: `DELETE /api/storage/volumes/{uuid}/snapshots/{snap_uuid}`.
2. If a temporary clone exists for this snapshot, delete it first.

### MountVolumeSnapshot (read-only access)

ONTAP snapshots are read-only. To provide host access:
1. Create a temporary FlexClone from the snapshot (like PowerStore pattern).
2. The clone contains the namespace at `/vol/<clone>/ns0`; map it to the subsystem.
3. Connect via NVMe/TCP.
4. On unmount: unmap, disconnect, delete the temporary clone.

### RestoreVolume

1. Use ONTAP snapshot restore action (ONTAP 9.12+ canonical endpoint): `POST /api/storage/volumes/{uuid}/snapshots/{snap_uuid}/actions/restore`.
2. Alternatively: FlexClone the snapshot into a new FlexVol, split it, swap as the current volume.

---

## Phase 5: Copy, Refresh, and Migration

**Goal:** Volume copy, refresh (incremental update), and cross-pool migration.

### CreateVolumeFromCopy

**Same-pool (optimized):**
1. FlexClone the source FlexVol.
2. Split clone (makes it independent).
3. Copy snapshots sequentially (ONTAP cannot atomically copy volume + snapshots in one operation).

**Cross-pool / cross-cluster:**
- Fall back to generic block+rsync migration via `MigrationTypes()`.

### RefreshVolume

1. Match source and destination snapshots.
2. For each new/changed snapshot: create on destination via data copy.
3. Use block-level rsync for delta sync.

### MigrationTypes

Full implementation following Pure Storage:

```go
func (d *ontap) MigrationTypes(contentType ContentType, refresh bool, copySnapshots bool) []migration.Type {
    var rsyncFeatures []string

    if shared.IsFalse(d.Config()["rsync.compression"]) {
        rsyncFeatures = []string{"xattrs", "delete", "bidirectional"}
    } else {
        rsyncFeatures = []string{"xattrs", "delete", "compress", "bidirectional"}
    }

    if refresh {
        var transportType migration.MigrationFSType

        if IsContentBlock(contentType) {
            transportType = migration.MigrationFSType_BLOCK_AND_RSYNC
        } else {
            transportType = migration.MigrationFSType_RSYNC
        }

        return []migration.Type{{FSType: transportType, Features: rsyncFeatures}}
    }

    if contentType == ContentTypeBlock {
        return []migration.Type{
            {FSType: migration.MigrationFSType_BLOCK_AND_RSYNC, Features: rsyncFeatures},
        }
    }

    return []migration.Type{
        {FSType: migration.MigrationFSType_RSYNC, Features: rsyncFeatures},
    }
}
```

---

## Phase 6: Optimized Image Storage (FlexClone)

**Goal:** Near-instant instance creation from images.

### EnsureImage

1. Create a "golden" FlexVol + NVMe namespace for the image.
2. Fill with image data.
3. Create an ONTAP snapshot on the image FlexVol (serves as clone base).

### CreateVolume from Image (optimized path)

1. FlexClone the image FlexVol from its snapshot (clone remains linked to parent by default).
2. Resize namespace if instance requires different size.
3. Result: writable volume that shares blocks with image — near-instant, space-efficient.

---

## Phase 7: Resize (SetVolumeQuota)

**Goal:** Online volume resize.

### Flow

1. Parse new size; enforce 4KiB alignment (ONTAP namespace size must be a multiple of 4096 bytes; validator uses `validate.IsMultipleOfUnit("4KiB")`).
2. Reject shrink for block volumes (unless filesystem supports it).
3. Resize FlexVol first (container must be large enough for namespace): `PATCH /api/storage/volumes/{uuid}`.
4. Resize namespace: `PATCH /api/protocols/nvme/namespaces/{uuid}` with new `space.size`.
5. Wait for local device to reflect new size (`connector.WaitDiskDeviceResize()`).
6. Resize filesystem if content type is FS.

---

## Phase 8: ListVolumes and Unknown Volume Discovery

**Goal:** Support `ListVolumes()` for import/recovery.

### Flow

1. List all FlexVols in the pool's aggregate using `listNamespaces()` scoped to the SVM.
2. Parse FlexVol name back to LXD volume type + UUID (reverse of Pure-style naming).
3. Return `[]Volume` with correct metadata.

---

## Phase 9: Backup and Restore

**Goal:** `BackupVolume()` and `CreateVolumeFromBackup()`.

### Strategy

Use generic block backup (same as Pure/PowerStore):
1. Map volume read-only.
2. Stream raw block data to tar writer.
3. Include volume config + snapshots metadata.

Restore is the reverse: create volume, map, write block data.

---

## Phase 10: Testing and Documentation

### Unit tests

- `driver_ontap_util_test.go` — Test volume name encoding/decoding, client request construction.

### Integration tests

- Extend `test/storage-vm` and `test/storage-volumes-vm` with ONTAP backend.
- Test lifecycle: pool create → volume create → snapshot → clone → resize → delete.
- Test NVMe connect/disconnect appears/disappears in `/sys/class/nvme-subsystem`.
- Test cluster scenarios (multi-node NVMe subsystem).

### Documentation

- `doc/reference/storage_ontap.md` — Configuration reference, requirements, examples.
- Update `doc/reference/storage_drivers.md` — Add ONTAP to the list.

---

## Implementation Order (Recommended)

| Order | Phase | Deliverable | Depends on |
|-------|-------|-------------|------------|
| 1 | Phase 0 | Skeleton compiles, driver registered | — |
| 2 | Phase 1 | REST client with job polling, tests | Phase 0 |
| 3 | Phase 2 | Pool create/delete/validate | Phase 1 |
| 4 | Phase 3 | Volume CRUD + mount/unmount | Phase 2 |
| 5 | Phase 4 | Snapshots | Phase 3 |
| 6 | Phase 6 | Optimized images (FlexClone) | Phase 4 |
| 7 | Phase 5 | Copy/refresh/migration | Phase 4 |
| 8 | Phase 7 | Resize | Phase 3 |
| 9 | Phase 8 | ListVolumes | Phase 3 |
| 10 | Phase 9 | Backup/restore | Phase 3 |
| 11 | Phase 10 | Tests + docs | All |

---

## NVMe/TCP Integration Notes

Per the architecture guide (Section 7a):

1. **Mode declaration:** Only `nvme` supported — validated in `Validate()`. Config key: `netapp.mode`.
2. **Kernel modules:** `connector.LoadModules()` loads `nvme_fabrics` + `nvme_tcp`.
3. **Host NQN:** Derived from LXD server UUID via `connector.QualifiedName()` → `nqn.2014-08.org.nvmexpress:uuid:<serverUUID>`.
4. **Target addresses:** Query the ONTAP appliance for NVMe-capable data LIF IPs via `GET /api/network/ip/interfaces?services=data_nvme_tcp`. Do not use the `nvme discover` CLI. If `netapp.target` is explicitly configured, connect only to those addresses; otherwise connect to all discovered data LIF addresses.
5. **Subsystem NQN:** ONTAP exposes a stable target NQN per NVMe subsystem. Retrieve it via `getSubsystem()` and pass to `connector.Connect()`.
6. **Device path:** Resolved via `/dev/disk/by-id/nvme-eui.<EUI>` using the block package helpers.
7. **Ports:** Default `4420` (data). Discovery port `8009` is not used — target addresses come from the appliance API.
8. **Error handling:** Connect failure after partial subsystem setup triggers full revert.
9. **Shutdown context:** Use `d.state.ShutdownCtx` for all long-running connector operations.

### ONTAP NVMe-specific API endpoints

| Operation | Endpoint |
|-----------|----------|
| List NVMe services | `GET /api/protocols/nvme/services?svm.name=<svm>` |
| Create NVMe subsystem | `POST /api/protocols/nvme/subsystems` |
| Get subsystem (with target NQN) | `GET /api/protocols/nvme/subsystems?name=<n>&svm.name=<svm>&fields=uuid,name,target_nqn` |
| Add host to subsystem | `POST /api/protocols/nvme/subsystems/{uuid}/hosts` |
| Remove host from subsystem | `DELETE /api/protocols/nvme/subsystems/{uuid}/hosts/{nqn}` |
| Create NVMe namespace | `POST /api/protocols/nvme/namespaces` |
| Map namespace to subsystem | `POST /api/protocols/nvme/subsystem-maps` |
| Unmap namespace from subsystem | `DELETE /api/protocols/nvme/subsystem-maps/{subsystem.uuid}/{namespace.uuid}` |
| Delete namespace | `DELETE /api/protocols/nvme/namespaces/{uuid}` |
| Get NVMe-capable data LIF IPs | `GET /api/network/ip/interfaces?services=data_nvme_tcp&svm.name=<svm>&fields=ip.address` |

---

## ONTAP-Specific Considerations

### FlexVol-per-namespace strategy

Each LXD volume gets its own FlexVol containing a single NVMe namespace. This enables:
- Per-volume snapshots (ONTAP snapshots are FlexVol-scoped).
- Per-volume FlexClone (for image optimization).
- Independent resize without affecting other volumes.
- Clean deletion (remove FlexVol = remove namespace + all snapshots).

### Thin provisioning

- FlexVol: guarantee = `none` (thin), fractional reserve = 0%.
- Namespace: space reservation = `false`.
- Controlled by `netapp.thin` config key.

### Job handling

- All mutating operations (POST/PATCH/DELETE) may return 202.
- Use `return_timeout=30` to maximize synchronous completions.
- Poll `GET /api/cluster/jobs/{uuid}` until `state` = `success` | `failure`.
- Use `d.state.ShutdownCtx` as the context for all polling loops.

### Error handling

- 404: Treat as "not found" → `(false, nil)` in `HasVolume()`, non-fatal in delete.
- 409: Distinguish "already exists" (adopt) from "in conflict" (fail).
- 429/503: Retry with exponential backoff (respect `Retry-After` header).
- Partial failures: Full revert via `revert.New()` pattern.

---

## Resolved Decisions

1. **NVMe namespace vs LUN mapping:** Use native NVMe namespaces (`/api/protocols/nvme/namespaces`) and NVMe subsystems exclusively. No iSCSI LUNs, igroups, or LUN maps.

2. **NVMe target address discovery:** Query the ONTAP appliance directly for NVMe-capable data LIF addresses via `GET /api/network/ip/interfaces?services=data_nvme_tcp`. Do not use the `nvme discover` CLI. If `netapp.target` is explicitly configured, connect only to those addresses; otherwise connect to all discovered data LIF addresses.

3. **ONTAP minimum version:** Require ONTAP 9.16+ (plan scope). Full NVMe/TCP namespace API is stable at this version.

4. **Clone split policy:** Keep FlexClones linked by default (space-efficient). Split only when the parent image is being deleted and linked clones still exist.

5. **Multi-path:** Connect to all available NVMe target addresses for HA. If `netapp.target` is explicitly configured, connect only to those specified addresses.

