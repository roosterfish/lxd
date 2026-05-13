# **Engineering Specification for the NetApp ONTAP Storage Driver in LXD**

The evolution of the Linux Container (LXD) ecosystem has been marked by a strategic expansion from local storage primitives to a sophisticated, pluggable architecture capable of orchestrating complex external storage appliances. This transformation is driven by the necessity of enterprise environments to unify container orchestration with high-availability, high-performance storage area networks (SAN) and network-attached storage (NAS) backends. To date, LXD has successfully integrated several major platforms, including Dell PowerFlex, Pure Storage, HPE Alletra, and Dell PowerStore, each providing a unique interpretation of block storage management within the container lifecycle.1 The proposed integration of the NetApp ONTAP appliance represents a significant milestone in this trajectory, introducing a storage driver that leverages the highly mature Write Anywhere File Layout (WAFL) architecture and the robust ONTAP REST API. This specification details the technical requirements, architectural mapping, and operational logic necessary to implement a native NetApp ONTAP driver for LXD, ensuring that it adheres to the established patterns of existing remote storage drivers while capitalizing on the specific efficiency and data protection features of the ONTAP ecosystem.

## **Architectural Foundation and API Integration**

The NetApp ONTAP storage driver must be built upon the ONTAP REST API, which, starting from version 9.6, has become the primary management interface for NetApp storage systems, replacing the legacy ONTAPI (ZAPI) protocols.3 The transition to a RESTful architecture is more than a change in syntax; it represents a shift toward resource-oriented management where every storage object—from the cluster itself down to individual LUNs and snapshots—is identified by a globally unique identifier (UUID).5 For the LXD driver, this reliance on UUIDs is critical for maintaining consistency in a clustered environment where object names might be subject to change or duplication across different Storage Virtual Machines (SVMs).  
The operational characteristics of the ONTAP REST API dictate the fundamental design of the driver’s communication layer. Requests are categorized based on their execution time, with synchronous processing reserved for operations completing in under two seconds, and asynchronous processing employed for more intensive storage tasks.5 Most volume management operations—such as creating a LUN, resizing a volume, or initiating a FlexClone—fall into the asynchronous category. In these scenarios, the API returns an HTTP 202 Accepted status and a job object containing a UUID.6 The LXD driver must implement a persistent polling mechanism to monitor these jobs until they reach a terminal state of success or failure. This ensures that LXD does not attempt to utilize a resource before the underlying storage hardware has fully provisioned it.

| API Characteristic | Mechanism in ONTAP REST API | Implication for LXD Driver |
| :---- | :---- | :---- |
| Resource Identification | 128-bit Globally Unique UUIDs 5 | Driver must store and reference UUIDs rather than names. |
| Request Execution | Synchronous (\<2s) and Asynchronous (\>2s) 5 | Driver must implement a job-state polling engine. |
| Object Persistence | UUIDs remain constant across renames 5 | Enables robust tracking of migrated volumes. |
| Authentication | Basic Auth and OAuth 2.0 (9.14+) 2 | Must support credential rotation and modern auth. |
| Response Headers | Location header contains the resource ID 5 | Immediate capture of IDs for new resources. |

A sophisticated feature of the ONTAP API that the driver should leverage is the return\_timeout query parameter. This allows the driver to specify a duration for which the API should attempt to complete the request synchronously before falling back to an asynchronous job.5 By setting a reasonable timeout, the driver can simplify its logic for fast operations while maintaining the robustness required for longer tasks.

## **Storage Pool Configuration and Initialization**

In the LXD storage model, a pool represents a cohesive collection of volumes and images. When integrating with NetApp ONTAP, a storage pool is logically mapped to a specific Storage Virtual Machine (SVM) and an underlying storage aggregate, often referred to as a local tier in modern ONTAP nomenclature.8 The SVM acts as a multi-tenant container, providing the network stack, authentication context, and management boundary for the storage.8  
The initialization of the pool requires the validation of the management endpoint and the authentication of the driver. Following the patterns of the Pure Storage and HPE Alletra drivers, the ONTAP driver must allow the user to specify the management URL, credentials, and the targeted SVM and aggregate.1 The driver must also verify that the required protocols—typically iSCSI or Fibre Channel (FC)—are enabled and configured on the SVM.11

| Configuration Key | Type | Requirement | Description |
| :---- | :---- | :---- | :---- |
| source | string | Mandatory | Name of the ONTAP SVM or resource path.8 |
| ontap.url | string | Mandatory | The REST API endpoint (e.g., https://mgmt.ontap.local/api).5 |
| ontap.username | string | Mandatory | The user account for management operations.5 |
| ontap.password | string | Mandatory | The password or token for the user account.5 |
| ontap.svm | string | Mandatory | The specific Storage Virtual Machine to utilize.8 |
| ontap.aggregate | string | Mandatory | The physical storage aggregate for volume allocation.8 |
| ontap.protocol | string | Optional | Storage protocol: iscsi (default) or fcp.11 |
| ontap.thin | boolean | Optional | Enable thin provisioning (default: true).7 |

During the pool creation phase, the driver performs a series of discovery calls. It must first retrieve the SVM's UUID and ensure that the specified aggregate has sufficient capacity.9 If the pool is configured for iSCSI, the driver must identify the Target Portal Group and the IQN of the SVM. For FC, it must discover the World Wide Node Names (WWNN) and Port Names (WWPN) of the target interfaces.11 This discovery process is essential for the subsequent "mapping" phase where LUNs are exposed to the LXD host.

## **Logical Unit Number (LUN) Lifecycle and Volume Management**

Within the LXD framework, storage volumes for instances and custom data are provisioned as block devices when using remote drivers.1 In the ONTAP ecosystem, these block devices are implemented as LUNs. A critical distinction of ONTAP is that LUNs must reside within a FlexVol volume.7 The driver has two architectural choices: it can create one large FlexVol to house all LUNs for the LXD pool, or it can create a separate FlexVol for every LUN. To align with NetApp's best practices for performance and data protection (such as snapshot isolation and volume-level replication), the driver should ideally create a FlexVol for each LUN, or at least for each instance.  
The creation of a LUN is initiated via a POST request to the /api/storage/luns endpoint.7 The payload must specify the SVM, the desired size, and the os\_type. Setting the os\_type to linux is vital, as it ensures the ONTAP system applies the correct SCSI geometry and alignment for Linux-based LXD hosts.4

JSON

{  
  "svm": { "name": "lxd\_svm" },  
  "name": "/vol/lxd\_vol\_01/lun\_01",  
  "os\_type": "linux",  
  "space": {  
    "size": "50GB",  
    "reserve": { "enabled": false }  
  }  
}

This request uses thin provisioning by disabling space reservations, allowing the ONTAP cluster to over-provision capacity—a common requirement in container environments.7 Once the LUN is created, the driver captures the UUID from the response to manage the volume throughout its lifecycle.  
The resizing of volumes in LXD is handled by a PATCH request to the LUN's UUID.4 This operation is particularly efficient in ONTAP, as the WAFL file system can dynamically expand or contract the logical boundaries of the LUN without relocating data blocks. However, the driver must coordinate this with the underlying FlexVol size; if a LUN is expanded beyond the capacity of its containing volume, the FlexVol itself must be resized first. This dependency management is a unique logic requirement for the ONTAP driver compared to more "flat" storage architectures like Pure Storage.10  
The deletion of a volume involves a multi-step teardown. The driver must first unmap the LUN from all host initiator groups, then delete the LUN, and finally—if the LUN was the sole occupant—delete the associated FlexVol. This ensures that the storage pool remains clean and prevents the accumulation of empty "metadata" volumes on the cluster.

## **Connectivity: Initiator Groups and LUN Mapping**

For an LXD host to access a provisioned LUN, the driver must manage the "mapping" relationship. This is governed by Initiator Groups (igroups), which are collections of host identifiers (IQNs for iSCSI or WWPNs for FC) that are granted access to specific storage resources.11  
When the first volume is mapped to an LXD host, the driver must ensure an igroup exists for that host. Following the convention of the Pure Storage driver, the igroup should be named after the LXD host to facilitate easy identification by storage administrators.10 The driver retrieves the host's initiators from the local system and creates the igroup via a POST to /api/protocols/san/igroups.11

| igroup Attribute | Value / Source | Relevance |
| :---- | :---- | :---- |
| name | LXD Hostname (e.g., lxd-node-01) | Identifies the host on the storage array.10 |
| os\_type | linux | Matches the LUN geometry and host OS.11 |
| protocol | iscsi or fcp | Restricts members to a specific protocol.11 |
| initiators | Array of IQNs or WWPNs | The physical/logical addresses of the LXD host.11 |

Once the igroup is established, the driver creates a LUN map using the /api/protocols/san/lun-maps endpoint.14 This mapping effectively links the LUN's UUID to the igroup's UUID. A critical enhancement for the ONTAP driver is the management of Selective LUN Map (SLM). In large clusters, SLM restricts the number of paths the host sees to the LUN, advertising it only through the nodes that own the volume and their high-availability partners.14 The driver should be configured to use these "reporting nodes" to minimize pathing complexity and prevent "ghost" devices from appearing on the host.

## **Data Efficiency: Snapshots and FlexClone Workflows**

One of NetApp's primary advantages is its native snapshotting and cloning technology. In LXD, snapshots are used for point-in-time recovery and as the basis for image management and instance cloning.1

### **Native Snapshot Operations**

The driver implements LXD snapshots using ONTAP's internal snapshot copies. These are created at the FlexVol level via the /api/storage/volumes/{uuid}/snapshots endpoint.15 Because an ONTAP snapshot captures the state of the entire volume, the "separate FlexVol per LUN" strategy mentioned earlier becomes essential for isolating snapshots to individual LXD volumes. This allows for near-instantaneous, zero-copy snapshots that do not impact the performance of other volumes in the pool.  
When a snapshot needs to be accessed—for example, to export a backup—the driver must create a temporary volume or LUN from that snapshot.10 This is because ONTAP snapshots are inherently read-only and reside within the metadata of the parent volume. By creating a temporary "clone" of the snapshot, the driver can map it to the host, allow LXD to read the data, and then destroy the temporary resource once the operation is complete.

### **Optimized Instance Creation with FlexClone**

LXD aims for "near instantaneous" instance creation by cloning a pre-made image volume rather than unpacking a tarball.1 The NetApp driver achieves this through FlexClone technology. A FlexClone is a writable, metadata-only copy of a parent volume or LUN.6  
When creating an instance from an image, the driver executes a POST to /api/storage/volumes with the clone property set to true.6 This creates a new FlexVol/LUN that shares all data blocks with the parent image. Only when the instance modifies its own data are new blocks written to the aggregate. This provides massive storage savings and performance benefits during "boot storms" where multiple instances are created from the same base image simultaneously.

JSON

{  
  "name": "instance\_vol\_v1",  
  "svm": { "name": "vs0" },  
  "clone": {  
    "parent\_volume": { "name": "ubuntu\_2204\_image" },  
    "is\_flexclone": "true"  
  }  
}

The response for a FlexClone operation is always asynchronous, returning a job object that the driver must monitor.6 The driver should also implement "clone splitting" logic if requested by the user, which decouples the clone from its parent to allow the parent image to be deleted or updated independently.6

## **Security, Observability, and Management**

Integrating a storage appliance into an automated infrastructure like LXD requires a robust approach to security and monitoring. The driver must not only manage data but also ensure that it does so within the constraints of enterprise security policies.

### **Role-Based Access Control (RBAC)**

The LXD driver should operate under a restricted user account that follows the principle of least privilege. Instead of using a cluster-admin account, the driver expects a custom role with access only to the necessary REST API paths.12 These paths include the storage and SAN management endpoints, as well as the cluster and job monitoring APIs.16

| Required API Path | Access Level | Purpose |
| :---- | :---- | :---- |
| /api/cluster | Read-Only | Discover cluster version and node health.12 |
| /api/storage/volumes | All | Create and manage FlexVols/FlexClones.16 |
| /api/storage/luns | All | Manage block storage resources.16 |
| /api/protocols/san/igroups | All | Manage host connectivity groups.16 |
| /api/protocols/san/lun-maps | All | Map LUNs to igroups.16 |
| /api/cluster/jobs | Read-Only | Monitor asynchronous operations.6 |

The driver can facilitate the setup of these permissions by providing documentation or scripts that administrators can run on the ONTAP cluster using the security login rest-role create commands.12

### **Monitoring and Observability**

To support LXD's metrics and monitoring capabilities, the driver must pull performance data from the ONTAP API. LUNs and volumes provide metric.\* and statistics.\* properties that report real-time throughput, IOPS, and latency.3 The driver should expose these metrics to LXD, allowing administrators to view the performance impact of specific containers on the storage fabric.

| Metric Type | ONTAP Attribute | LXD Equivalent |
| :---- | :---- | :---- |
| Latency | metric.latency | I/O Latency |
| Throughput | metric.throughput\_raw | Read/Write Bytes/sec.3 |
| IOPS | metric.iops | Read/Write Ops/sec.7 |
| Space Used | space.used | Volume Used Space.3 |
| Provisioned Size | space.size | Volume Total Size.7 |

Additionally, the driver should log its API interactions. Accessing the REST API log on the ONTAP system can assist in troubleshooting, as it provides a record of every call made by the driver and the corresponding JSON responses.17

## **Comparative Analysis and Strategic Differentiation**

The NetApp ONTAP driver joins a competitive field of remote storage drivers in LXD. To justify its implementation, it must provide clear advantages over existing options like Dell PowerStore or Pure Storage.

### **ONTAP vs. Pure Storage and Dell PowerStore**

While the Pure Storage driver is praised for its simplicity and the use of "temporary volumes" for snapshot access 10, the ONTAP driver offers superior multi-tenancy through the SVM architecture. This allows a single LXD cluster to securely share a storage array with other enterprise applications, with each department or project isolated within its own SVM.8  
Compared to the Dell PowerStore and PowerFlex implementations, ONTAP's WAFL file system provides more efficient data reduction and snapshotting. The FlexClone mechanism is more granular, allowing for thousands of near-instantaneous clones in a single pool—a scale that is often required in high-density container environments.6

| Feature | NetApp ONTAP | Pure Storage | Dell PowerStore |
| :---- | :---- | :---- | :---- |
| **Thin Provisioning** | WAFL-native, highly efficient.7 | Block-level thin provisioning.10 | Native block compression.1 |
| **Snapshots** | FlexVol-level, near-zero impact.6 | Volume-level snapshots.10 | Managed block snapshots.1 |
| **Cloning** | FlexClone (Metadata-only).6 | Volume Copy.10 | Thin Clones.1 |
| **Multitenancy** | Storage Virtual Machines (SVM).8 | Basic volume grouping. | Resource Pools. |
| **Protocols** | iSCSI, FC, NVMe, NFS, SMB.11 | iSCSI, FC, NVMe.10 | iSCSI, FC, NVMe.1 |

### **Advanced Workflows: SnapMirror and Replication**

A significant future-proofing element for the ONTAP driver is the integration of SnapMirror replication.18 By leveraging ONTAP's native replication capabilities, the LXD driver could eventually support cross-site disaster recovery. An instance running in one LXD cluster could be replicated at the storage layer to a second cluster, allowing for rapid failover with minimal data loss. This level of integrated data protection is a hallmark of NetApp and provides a clear path for LXD to penetrate the mission-critical workload market.

## **Implementation Details and Failure Modes**

The implementation of the driver must be resilient to common storage networking issues. The driver should handle "partial state" where a LUN is created but the mapping fails. In such cases, the driver must perform an automatic rollback to prevent the exhaustion of the cluster's LUN and volume limits.

### **Handling Conflict and Race Conditions**

As LXD is often used in clustered environments, multiple nodes may attempt to manage storage simultaneously. The ONTAP API uses HTTP 409 Conflict errors when a resource with the same name already exists.19 The driver must be intelligent enough to distinguish between a "fatal" conflict and an "expected" one. For example, if an igroup for a host already exists, the driver should simply adopt the existing UUID and proceed with the mapping, rather than failing the operation.19

### **Optimized Transfer and Image Management**

The driver must support LXD's optimized transfer path. When moving an instance between two storage pools on the same ONTAP cluster, the driver should use a volume move or LUN clone operation rather than transferring data over the network.1 This significantly reduces the load on the host's networking stack and accelerates cluster rebalancing operations.

## **Conclusion**

The NetApp ONTAP storage driver represents a highly sophisticated addition to the LXD storage ecosystem. By leveraging the ONTAP REST API and its resource-oriented architecture, the driver provides a reliable, scalable, and efficient bridge between system containers and enterprise storage.3 The use of FlexVols and LUNs as the primary storage primitives ensures compatibility with existing LXD workflows, while the integration of FlexClone and native snapshots provides the performance required for modern cloud-native applications.6 Through a combination of robust job-state monitoring, granular RBAC, and advanced data efficiency features, the ONTAP driver empowers organizations to deploy LXD at scale within the most demanding data center environments.5 This specification serves as the blueprint for an implementation that is not only functional but also deeply integrated into the strategic capabilities of the NetApp storage platform.

#### **Works cited**

1. Storage drivers \- LXD documentation 6.8, accessed May 12, 2026, [https://documentation.ubuntu.com/lxd/latest/reference/storage\_drivers/](https://documentation.ubuntu.com/lxd/latest/reference/storage_drivers/)  
2. Storage drivers \- Ubuntu documentation, accessed May 12, 2026, [https://documentation.ubuntu.com/lxd/stable-5.21/reference/storage\_drivers/](https://documentation.ubuntu.com/lxd/stable-5.21/reference/storage_drivers/)  
3. NetApp OnTap (Remote) extension \- Dynatrace Documentation, accessed May 12, 2026, [https://docs.dynatrace.com/docs/observe/infrastructure-observability/extensions/netapp-ontap-remote-1](https://docs.dynatrace.com/docs/observe/infrastructure-observability/extensions/netapp-ontap-remote-1)  
4. lun \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restmap/lun.html](https://docs.netapp.com/us-en/ontap-restmap/lun.html)  
5. Operational characteristics of the ONTAP REST API \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-automation/rest/operational\_characteristics.html](https://docs.netapp.com/us-en/ontap-automation/rest/operational_characteristics.html)  
6. ONTAP 9.18.1 REST API reference \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restapi/storage\_volumes\_endpoint\_overview.html](https://docs.netapp.com/us-en/ontap-restapi/storage_volumes_endpoint_overview.html)  
7. Storage luns endpoint overview \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restapi/storage\_luns\_endpoint\_overview.html](https://docs.netapp.com/us-en/ontap-restapi/storage_luns_endpoint_overview.html)  
8. Manage ONTAP in ONTAP-mode | NetApp Volumes \- Google Cloud Documentation, accessed May 12, 2026, [https://docs.cloud.google.com/netapp/volumes/docs/ontap/manage-ontap](https://docs.cloud.google.com/netapp/volumes/docs/ontap/manage-ontap)  
9. Cluster Administration | PDF \- Scribd, accessed May 12, 2026, [https://www.scribd.com/document/697248862/Cluster-Administration](https://www.scribd.com/document/697248862/Cluster-Administration)  
10. Pure Storage \- LXD \- Ubuntu documentation, accessed May 12, 2026, [https://documentation.ubuntu.com/lxd/stable-5.21/reference/storage\_pure/](https://documentation.ubuntu.com/lxd/stable-5.21/reference/storage_pure/)  
11. Protocols san igroups endpoint overview \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restapi/protocols\_san\_igroups\_endpoint\_overview.html](https://docs.netapp.com/us-en/ontap-restapi/protocols_san_igroups_endpoint_overview.html)  
12. Configure ONTAP user roles and privileges for ONTAP tools \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-tools-vmware-vsphere-10/configure/configure-user-role-and-privileges.html](https://docs.netapp.com/us-en/ontap-tools-vmware-vsphere-10/configure/configure-user-role-and-privileges.html)  
13. Qtrees and ONTAP FlexVol volume partitioning \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap/volumes/qtrees-partition-your-volumes-concept.html](https://docs.netapp.com/us-en/ontap/volumes/qtrees-partition-your-volumes-concept.html)  
14. Protocols san lun-maps endpoint overview \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restapi/protocols\_san\_lun-maps\_endpoint\_overview.html](https://docs.netapp.com/us-en/ontap-restapi/protocols_san_lun-maps_endpoint_overview.html)  
15. Storage volumes volume.uuid snapshots endpoint overview \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-restapi/storage\_volumes\_volume.uuid\_snapshots\_endpoint\_overview.html](https://docs.netapp.com/us-en/ontap-restapi/storage_volumes_volume.uuid_snapshots_endpoint_overview.html)  
16. NetBackup™ Snapshot Manager for Data Center Administrator's Guide \- Veritas, accessed May 12, 2026, [https://www.veritas.com/content/support/en\_US/doc/155729295-155729314-1](https://www.veritas.com/content/support/en_US/doc/155729295-155729314-1)  
17. Accessing the REST API log \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap/task\_rest\_access\_log.html](https://docs.netapp.com/us-en/ontap/task_rest_access_log.html)  
18. Allow generation of ONTAP reports using the ONTAP REST API \- NetApp Docs, accessed May 12, 2026, [https://docs.netapp.com/us-en/ontap-automation/workflows/wf\_rbac\_role\_ontap\_reports.html](https://docs.netapp.com/us-en/ontap-automation/workflows/wf_rbac_role_ontap_reports.html)  
19. REST API Fails to Create NFS Export Policy Rules with HTTP 409 Conflict, accessed May 12, 2026, [https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/REST\_API\_Fails\_to\_Create\_NFS\_Export\_Policy\_Rules\_with\_HTTP\_409\_Conflict](https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/REST_API_Fails_to_Create_NFS_Export_Policy_Rules_with_HTTP_409_Conflict)