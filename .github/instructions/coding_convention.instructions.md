name: coding_convention
description: "Use when implementing or modifying LXD storage drivers, remote storage volume mapping, and storage backend-driver integration in lxd/storage/drivers and related storage backend files. Enforces naming, implementation flow, validation, revert safety, snapshot/copy, and support for different instance/custom volume (block, filesystem volumes) patterns."
applyTo: 
  - "lxd/storage/drivers/driver_*.go"
  - "lxd/storage/drivers/load.go"
  - "lxd/storage/drivers/interface.go"
  - "lxd/storage/backend_lxd.go"
  - "lxd/storage/pool_interface.go"
---
# Storage Driver Coding Convention

## Implementation Flow

- Start from a written specification for the driver and confirm any backend API constraints before coding.
- Keep the driver split into three files when practical: core pool logic in the main driver file, volume logic in a `_volumes` file, and backend API helpers in a `_utils` file.
- Register the driver in `lxd/storage/drivers/load.go` once the core pool path is ready.
- Implement pool creation, deletion, mount, and unmount together with the base volume create and delete paths first so the driver can be exercised early.
- Add snapshots, copy, refresh, and migration after the basic lifecycle works.
- Treat migration and cross-member movement as cluster features and validate them in a clustered setup.
- Most remote storage drivers do not support buckets; only CephObject is a bucket-only remote storage driver.
- If the driver depends on additional OSS software, make sure the snap packaging is updated so LXD can ship and use it.
- Add a new documentation page under `doc/reference` for any driver that is meant to be included in LXD.
- Test locally against the real storage array when possible, then extend coverage with `test/storage-vm` and `test/storage-volumes-vm` in LXD-CI.

## Naming

- Name the driver struct as a lowercase driver identifier used by the loader map: `alletra`, `pure`, `powerflex`, `powerstore`.
- Keep package-level one-time load state as `<driverName>Loaded` and version string as `<driverName>Version`.
- Name supported connector list `<driverName>SupportedConnectors`.
- Use `d` as the receiver name for driver methods.
- Keep helper names consistent with existing driver patterns:
  - `connector()` and `client()` for lazy-initialized dependencies.
  - `getVolumeName()` for backend volume name translation.
  - `ensureHost()`, `mapVolume()`, `unmapVolume()`, `getMappedDevPath()` or `getMappedDevicePath()` for host mapping flows.
  - Public interface methods should delegate to lower-case helpers where appropriate (for example `CreateVolumeSnapshot()` and `createVolumeSnapshot()`).
- Keep config keys lowercase and driver-prefixed for pool options (for example `powerstore.gateway`, `pure.mode`) and use shared keys for volume options (`volume.size`, `block.filesystem`, `block.mount_options`).
- If the backend has a volume name length limitation, always use the volume UUID (or a UUID-derived string) as the storage volume name. See `UUIDVolumeNames: true` in drivers like PowerFlex, PowerStore, and Pure. Remove hyphens from the UUID if needed to fit length constraints. Document the naming logic in the driver and ensure decode/parse helpers are robust.

## Comments And Errors

- Add doc comments to exported methods. Start comment text with the method name and end with a period.
- Use gerund error phrasing:
  - Good: `Failed creating volume %q: %w`.
  - Avoid: `Unable to create volume`.
- Use `Cannot` instead of `Unable to` in non-wrapped direct errors.
- Use `%q` for identifiers and `%w` when wrapping errors.

## Validation And Config Style

- In `Validate()`, define a `rules` map and call `d.validatePool(config, rules, d.commonVolumeRules())` first.
- Preserve `lxdmeta:generate` annotations above rule entries for storage documentation generation.
- Enforce immutable transport mode after creation (reject mode changes if old mode is set and differs from new mode).
- Validate selected connector mode support with `connectors.NewConnector(...)` plus `LoadModules()`.
- In `ValidateSource()`, check required remote endpoint and credential fields explicitly and return clear errors for missing keys.

## Revert And Cleanup Safety

- Use `revert := revert.New()` plus `defer revert.Fail()` in mutating functions.
- Add cleanup immediately after each side effect.
- On success, call `revert.Success()` before returning.
- If returning cleanup hooks from helpers, return `revert.Clone().Fail` after success.
- In cleanup closures, do not silently ignore failures: log warnings when relevant.

## Volume Lifecycle Patterns

- For volume create/copy/refresh/delete flows, keep VM block companion handling consistent:
  - Check `vol.IsVMBlock()`.
  - Operate on `vol.NewVMBlockFilesystemVolume()` as needed.
  - Ensure revert hooks include companion volume rollback.
- Keep `FillVolumeConfig()` behavior consistent:
  - Inherit `volume.*` pool keys.
  - Handle `block.filesystem` and `block.mount_options` explicitly.
  - Force VM filesystem defaults where needed.
- In `ValidateVolume()`, remove `block.*` rules for custom block volumes and normalize ISO size according to driver constraints.


## Snapshot, Copy, Refresh, And Optimized Image Storage

- Implement snapshot copy/refresh behavior explicitly when backend APIs do not support atomic copy-with-snapshots.
- Match snapshots by short snapshot name and update parent UUID relations correctly.
- Use private helper orchestration (`refreshVolume`, `createVolumeSnapshot`) to avoid duplicated logic across public methods.
- For snapshot mount paths that require temporary clones, isolate clone naming and cleanup logic clearly.
- If the backend supports optimized image storage (e.g., native volume cloning, deduplication, or zero-copy image instantiation), implement the logic in the driver:
  - Detect optimized image support in `Info()` and expose via the `OptimizedImages` field.
  - Implement `CreateVolumeFromImage()` and/or `CreateInstanceFromImage()` to use backend-native clone/copy paths for images.
  - Ensure fallback to generic copy if optimized path is unavailable or fails.
  - Document any backend-specific requirements or limitations for optimized image storage in the driver doc page.

## Mounting And Device Mapping

- Implement `MountVolume()` and `UnmountVolume()` through shared helpers where possible.
- Keep mapping flow deterministic:
  - ensure host
  - map/attach
  - connect connector
  - resolve disk path
- Keep unmap flow deterministic:
  - remove disk device
  - detach mapping
  - disconnect when last use is gone
  - remove host/session state if applicable
- Use `d.state.ShutdownCtx` for connector waits and long-running device operations.

## API Error Handling

- Use `api.StatusErrorCheck(err, http.StatusNotFound)` to distinguish not-found from hard failures.
- For delete operations, treat not-found as non-fatal when idempotency is expected.
- Keep `HasVolume()` behavior consistent: return `(false, nil)` on not-found.
