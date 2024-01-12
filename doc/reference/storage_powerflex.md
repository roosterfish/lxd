(storage-powerflex)=
# Dell PowerFlex - `powerflex`

[Dell PowerFlex](https://www.dell.com/en-us/dt/storage/powerflex.htm) is a software-defined storage solution from [Dell Technologies](https://dell.com). Among other things it offers the consumption of redundant block storage across the network.

LXD offers access to PowerFlex storage clusters by making use of the NVMe/TCP transport protocol.
In addition, PowerFlex offers copy-on-write snapshots, thin provisioning and other features.

To use PowerFlex, make sure you have the required kernel modules installed on your host system.
On Ubuntu these are `nvme_fabrics` and `nvme_tcp`, which come bundled in the `linux-modules-extra-$(uname -r)` package.

## Terminology

PowerFlex groups various so-called {abbr}`SDS (storage data servers)` under logical groups within a protection domain.
Those SDS are the hosts that contribute storage capacity to the PowerFlex cluster.
A *protection domain* contains storage pools, which represent a set of physical storage devices from different SDS.
LXD creates its volumes in those storage pools.

You can take a snapshot of any volume in PowerFlex, which will create an independent copy of the parent volume.
PowerFlex volumes get added as a NVMe drive to the respective LXD host the volume got mapped to.
For this, the LXD host connects to one or multiple NVMe {abbr}`SDT (storage data targets)` provided by PowerFlex.
Those SDT run as components on the PowerFlex storage layer.

## `powerflex` driver in LXD

The `powerflex` driver in LXD uses PowerFlex volumes for custom storage volumes, instances and snapshots.
For storage volumes with content type `filesystem` (containers and custom file-system volumes), the `powerflex` driver uses volumes with a file system on top (see [`block.filesystem`](storage-powerflex-vol-config)).
By default, LXD creates thin-provisioned PowerFlex volumes.

LXD expects the PowerFlex protection domain and storage pool already to be set up.
Furthermore, LXD assumes that it has full control over the storage pool.
Therefore, you should never maintain any volumes that are not owned by LXD in a PowerFlex storage pool, because LXD might delete them.

This driver behaves differently than some of the other drivers in that it provides remote storage.
As a result and depending on the internal network, storage access might be a bit slower than for local storage.
On the other hand, using remote storage has big advantages in a cluster setup, because all cluster members have access to the same storage pools with the exact same contents, without the need to synchronize storage pools.

When creating a new storage pool using the `powerflex` driver, LXD tries to discover one of the SDT from the given storage pool.
Alternatively, you can specify which SDT to use with [`powerflex.sdt`](storage-powerflex-pool-config).
LXD instructs the NVMe initiator to connect to all the other SDT when first connecting to the subsystem.

Due to the way copy-on-write works in PowerFlex, snapshots of any volume don't rely on its parent.
As a result, volume snapshots are fully functional volumes themselves, and it's possible to take additional snapshots from such volume snapshots.
This tree of dependencies is called the *PowerFlex vTree*.
Both volumes and their snapshots get added as standalone NVMe disks to the LXD host.

(storage-powerflex-volume-names)=
### Volume names

Due to a [limitation](storage-powerflex-limitations) in PowerFlex, volume names cannot exceed 31 characters.
In order for LXD to identify the volume types and snapshots, special identifiers are appended to the volume names:

Type            | Identifier   | Example
:--             | :---         | :----------
Container       | `c_`         | `c(_project1)_c1`
Virtual machine | `v_`         | `v(_project2)_v1`
Image           | `i_`         | `i(_project3)_img`
Custom volume   | `u_`         | `u(_project4)_vol`

When creating volumes in the `default` project, its identifier is omitted.
This does not apply for custom storage volumes, since their name may contain an underscore (which could
potentially lead to inconsistencies when running the `lxd recover` command).

Volumes for virtual machines and ISO files use two additional characters internally.
The VMs root volume contains the `.b` block suffix whilst an ISO file ends on `.i`.

To have enough space for the snapshot identifier, at least two more characters must be
reserved. You can try keeping the snapshots name at a minimum by setting [`snapshots.pattern`](storage-powerflex-snapshot-pattern)
to `%d`. This will result in the following volume names:

* Snapshot `snap0` for a virtual machine `v1`: `v_project1_v1@0`
* Snapshot `snap1` for a custom volume `vol`: `u_project1_vol@1`

In any case make sure the instance name including all of its identifiers is short enough to also fit the name of the snapshot.

(storage-powerflex-limitations)=
### Limitations

The `powerflex` driver has the following limitations:

Limit of snapshots in a single vTree
: An internal limitation in the PowerFlex vTree does not allow to take more than 126 snapshots of any volume in PowerFlex.
  This limit also applies to any child of any of the parent volume's snapshots.
  A single vTree can only have 126 branches.

Non-optimized image storage
: Due to the limit of 126 snapshots in the vTree, the PowerFlex driver doesn't come with support for optimized image storage.
  This would limit LXD to create only 126 instances from an image.
  Instead, when launching a new instance, the image's contents get copied to the instance's root volume.

Copying volumes
: PowerFlex does not support creating a copy of the volume so that it gets its own vTree.
  Therefore, LXD falls back to copying the volume on the local system.
  This implicates an increased use of bandwidth due to the volume's contents being transferred over the network twice.

Volume size constraints
: In PowerFlex, the size of a volume must be in multiples of 8 GiB.
  This results in the smallest possible volume size of 8 GiB.
  However, if not specified otherwise, volumes are getting thin-provisioned by LXD.
  PowerFlex volumes can only be increased in size.

Volume name size limitation
: In PowerFlex, the name of a volume cannot exceed 31 characters.
  LXD uses certain identifiers to indicate the purpose of a volume in the storage backend.
  See the section on [Volume names](storage-powerflex-volume-names) for more information.

Sharing custom volumes between instances
: The PowerFlex driver "simulates" volumes with content type `filesystem` by putting a file system on top of a PowerFlex volume.
  Therefore, custom storage volumes can only be assigned to a single instance at a time.

Sharing the PowerFlex storage pool between installations
: Sharing the same PowerFlex storage pool between multiple LXD installations is not supported.
  Due to the volume name limitations, no extra identifier can be added to distinguish between installations.

## Configuration options

The following configuration options are available for storage pools that use the `powerflex` driver and for storage volumes in these pools.

(storage-powerflex-pool-config)=
### Storage pool configuration

Key                        | Type   | Default             | Description
:--                        | :---   | :------             | :----------
`powerflex.gateway`        | string | -                   | Address of the PowerFlex Gateway
`powerflex.gateway.verify` | bool   | `true`              | Whether to verify the PowerFlex Gateway's certificate
`powerflex.user.name`      | string | `admin`             | User for PowerFlex Gateway authentication
`powerflex.user.password`  | string | -                   | Password for PowerFlex Gateway authentication
`powerflex.pool`           | string | -                   | ID of the PowerFlex storage pool (if you want to specify the storage pool via its name, also set `powerflex.domain`)
`powerflex.domain`         | string | -                   | Name of the PowerFlex protection domain (only required if `powerflex.pool` is specified using its name)
`powerflex.mode`           | string | the discovered mode | Gets discovered automatically if the system provides the necessary kernel modules; currently, only `nvme` is supported
`powerflex.sdt`            | string | one of the SDT      | PowerFlex NVMe/TCP SDT
`powerflex.clone_copy`     | bool   | `false`             | Make a non-sparse copy when creating a snapshot of instances or custom volumes (see the [vTree limitations](storage-powerflex-limitations))
`volume.size`              | string | `8GiB`              | Minimal storage size for PowerFlex volumes

{{volume_configuration}}

(storage-powerflex-vol-config)=
### Storage volume configuration

Key                     | Type      | Condition                                         | Default                              | Description
:--                     | :---      | :--------                                         | :------                              | :----------
`block.type`            | string    |                                                   | `thin`                               | Create a `thin`  or `thick` provisioned volume
`block.filesystem`      | string    | block-based volume with content type `filesystem` | same as `volume.block.filesystem`    | {{block_filesystem}}
`block.mount_options`   | string    | block-based volume with content type `filesystem` | same as `volume.block.mount_options` | Mount options for block-backed file system volumes
`security.shifted`      | bool      | custom volume             | same as `volume.security.shifted` or `false`   | {{enable_ID_shifting}}
`security.unmapped`     | bool      | custom volume             | same as `volume.security.unmapped` or `false`  | Disable ID mapping for the volume
`size`                  | string    |                           | same as `volume.size`                          | Size/quota of the storage volume
`snapshots.expiry`      | string    | custom volume             | same as `volume.snapshots.expiry`              | {{snapshot_expiry_format}}
`snapshots.pattern`     | string    | custom volume             | same as `volume.snapshots.pattern` or `snap%d` | {{snapshot_pattern_format}} [^*]
`snapshots.schedule`    | string    | custom volume             | same as `volume.snapshots.schedule`            | {{snapshot_schedule_format}}

(storage-powerflex-snapshot-pattern)=
[^*]: {{snapshot_pattern_detail}}
