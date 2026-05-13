Before getting started with LXD, you can find some preliminary information about contributions [here](https://github.com/canonical/lxd/blob/main/CONTRIBUTING.md).  
For starting the development [this guide](https://documentation.ubuntu.com/lxd/en/latest/installing/#install-lxd-from-source) is a good first step which helps you building LXD from source and running it on your local system.  
A more advanced configuration (including the LXD snap) is to [sideload custom binaries](https://discourse.ubuntu.com/t/building-custom-lxd-binaries-for-side-loading-into-an-existing-snap-installation/37327). This is especially helpful for tests later in the process as it allows injecting the new code into the packaged snap.

General information about storage pools can be found [here](https://documentation.ubuntu.com/lxd/en/latest/explanation/storage/).  
To get familiar with the management of storage entities in LXD also check out the [how-tos](https://documentation.ubuntu.com/lxd/en/latest/storage/).

Before the implementation can start, we require a specification that depicts the details of the implementation.  
As an example check out the [spec about the PowerFlex storage driver](https://discourse.ubuntu.com/t/dell-powerflex-storage-driver/40611) or the [spec about the Pure storage driver](https://docs.google.com/document/d/1H6SXOYEhGEpQJBKfQjT42kjK3YgQ6bjOS6xPFUmR3Dg/edit?tab=t.0).

The storage drivers for LXD are implemented under [lxd/storage/drivers](https://github.com/canonical/lxd/tree/main/lxd/storage/drivers).  
For each of the different drivers (e.g. PowerFlex) you will usually find three files suffixed with "\_utils", "\_volumes" and one without.  
This helps separating the logic into three different sections:

* Core storage pool related code (no suffix) e.g. [driver\_powerflex.go](https://github.com/canonical/lxd/blob/main/lxd/storage/drivers/driver_powerflex.go)  
* Volume related code (\_volumes) e.g. [driver\_powerflex\_volumes.go](https://github.com/canonical/lxd/blob/main/lxd/storage/drivers/driver_powerflex_volumes.go)  
* Utilities (\_utils) e.g. [driver\_powerflex\_utils.go](https://github.com/canonical/lxd/blob/main/lxd/storage/drivers/driver_powerflex_utils.go)

Usually the utilities file contains code responsible to talk with the respective storage array through an API.

Making the storage driver available to LXD works by appending an additional line to the [drivers map](https://github.com/canonical/lxd/blob/main/lxd/storage/drivers/load.go#L8).  
Now when you build LXD you can select your driver when creating new storage pools using "lxc storage pool create \<driver\> \<name\>".

Most of the remote storage drivers don’t support buckets. Currently there is only one remote storage driver solely used to provide buckets which is CephObject.

In general it is a good idea to first implement the various Mount/Unmount driver functions together with the pool Create/Delete and volume Create/Delete functions to test the basic functionality of the storage drivers.  
In the next step the support for snapshots, copy, move (migration) can be added.  
For the latter a LXD cluster is required to be able to move storage volumes across cluster members.

Testing the storage driver locally requires having access to the respective storage array.  
As we also run an extensive test suite for LXD, automated tests can be found both in [LXD](https://github.com/canonical/lxd/tree/main/test) and our dedicated [LXD-CI](https://github.com/canonical/lxd-ci) repository.  
Letting the new driver pass the [tests/storage-vm](https://github.com/canonical/lxd-ci/blob/main/tests/storage-vm) and [tests/storage-volumes-vm](https://github.com/canonical/lxd-ci/blob/main/tests/storage-volumes-vm) would be a good starting point.  
Ideally the storage array can be deployed as part of the pipeline to have some automated tests too.

If a driver is to be included into LXD, there also has to be a [new page](https://github.com/canonical/lxd/tree/main/doc/reference) in the docs documenting it.

Last but not least, depending on the array there might be additional software required that is leveraged by LXD to interact with the array.  
As LXD is shipped as a snap, this software (if OSS) also has to be configured to be part of the [LXD snap package](https://github.com/canonical/lxd-pkg-snap/).

Revert: [https://github.com/canonical/lxd/blob/main/shared/revert/revert.go](https://github.com/canonical/lxd/blob/main/shared/revert/revert.go)  
