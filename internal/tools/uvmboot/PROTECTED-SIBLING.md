# Protected sibling pair: operator runbook

This is the default-off SNP Linux experiment, not a
production isolation guarantee. Source acceptance is **not** build, deployment,
or hardware acceptance. The hardware commands below remain manual acceptance
steps; source and fixture checks do not replace them. The standalone workflow
is preserved; the reduced containerd-owned profile is described separately below.

The 2026-11-10 upstream integration supersedes the earlier transport-v3 pin.
Use hcsshim branch
`experiment/lcow-protected-shared-memory-snp-proof-upstream-20261110`,
including upstream `47148464142b7303ac4241e2467b043d95c2055e`;
OS merge `87fdcc6efd484b685c7de5eeb488542be06b060e`, including native event-range
commit `44a40a94234400df1c55803f27fd14afcaf3a7f5`; and vsock-tun-forward branch
`protected-shared-hcs-v1-upstream-20261110` at
`203341899db940bc4165507f0371a1eed10d5949`.
Record the actual revisions and deployed artifacts for every attempt.

Transport **v4 is the shared requirement for ordinary and protected startup**,
using the common `sibling.TransportVersion` constant. There is no protected-only
selector, compatibility flag, negotiation, or acceptance of v3.
Rebuild and deploy the matched native host, launcher, kernel, IGVM and modules;
changing a launcher check cannot make old guest artifacts compatible.

## 1. Match the entire stack before launching

Use an elevated Windows SNP lab host and exactly two Linux VMs. The legacy
profile gives each a direct RP-attached dm-verity root and direct host GCS.
The combined profile below mediates only the workload root and GCS.
Supply the actual current IGVM-derived
`kernel.vmgs` and its matching `rootfs.vhd` in the boot directory. Record the
IGVM/kernel build inputs and hash as well as the VMGS/rootfs hashes: the CLI
consumes the VMGS, not a separate invented `--igvm` argument. Kernel, modules,
rootfs, GCS and runtime tools must agree. Arbitrary storage exports,
appliance/Unikraft, OpenShell, benchmarks, mapping-only/inventory,
and the old protected diagnostic/two-proof lifecycle remain unsupported.
Owned startup requires the reduced profile below, not these standalone CLI flags.

Deploy the matched native product set through the established lab process:
VID DLL **and** driver, worker memory/VMB components, common shared-region
library, DynMem, HCS management, private schemas and generated IDL/proxy products.
The new DLL export is `VidCreateProtectedSharedParticipant`; the new **local**
COM interface is `IVmProtectedSharedMemoryImport1`,
IID `{34DDCA55-73DC-42A7-B4D7-0FD5A6717FBB}`. Existing controller control v2
uses a 48-byte request and 40-byte result. The new import has its own versioned
envelope; do not reinterpret it as that control request or mix an old DLL with
new callers. Generate from `.mars`, `.idl` and `vid.src`, not hand-edited output.
Check the complete proxy aggregate, including existing worker interfaces; a
successfully linked partial proxy is insufficient.

Beside the selected `sibling_bus.ko`, provide matching `diode_netvsp.ko`,
`diode_tcpbulk`, `diode_vsock_test`, `diode_iperf`, `demo.sh`, `covert_udp`,
`diode_tcpdump`, `diode_tc`, `diode_iptables`, `collect-page-metadata.sh`, and
`ahv-guest-ctl`. Missing/nonregular tools fail preflight before backing allocation.
The AHV CLI must match the replacement host ABI, built-in guest collector and
AHVF v4/AHVW v2 contracts; the integration revisions above are historical
baselines, not sufficient AHV build pins. Old Linux binaries and Windows
`ahvtrigger` are incompatible; there is no fallback to retired calls or v1 wire.
The workload uses the matched kernel's stock `hv_netvsc`/`hv_sock` sibling
transport; it does not load a
replacement workload IP driver. Ordinary baseline only also needs the matching
`hcs_shmem_diag.ko`. A stale module is not repaired by choosing a different GPA.

The native/guest discovery contract is descriptor **v2, 54 bytes**. The host
adds `EventFlagCount` at byte offset 52 after the range base at offset 50, and
provisions **33 native event flags**: relative flag 0 for control and flags
1 through 32 for service notifications. Guests signal relative flags, not the
absolute range base.
Separately, the guest-to-guest wire protocol is **transport v4**
(`SIBLING_BUS_VERSION`); that is the version reported by `sibling_instance`
and checked by the launcher. Protocol consumers are in the guests; changing
the launcher guard does not convert descriptors or wire layouts. Both native
descriptor v2 and guest transport v4 are required by this integrated stack.

The descriptor gate admits page-aligned lengths from `0x20000` through
32 MiB, inclusive, with aligned, nonzero, nonwrapping GPA. The launcher uses
4-KiB pages. Passing that gate does **not** guarantee enough space for every
transport/service allocation. The 1-MiB example below is an input, not a capacity
or hardware-success claim.

For each run, save actual source revisions, toolchain versions, build
configuration, native file versions/PDB identities, final packaged/deployed
hashes, boot/tool hashes, exact command line, run/VM IDs, lease, byte GPAs,
UTC timestamps, stdout/stderr and cleanup outcome in a user-created evidence
directory. For example, inspect real files with
`Get-FileHash -Algorithm SHA256 -LiteralPath $Launcher` and
`(Get-Item -LiteralPath $Launcher).VersionInfo`; repeat for the actual artifacts.
Signing can change an object-output image's raw hash. Investigate differences;
require exact final binplaced/package/deployed hashes where no transformation
is expected.

## 2. Establish the ordinary baseline, then protected startup

In elevated PowerShell, enter existing lab paths (no sample path is a deployed
artifact). Use a fresh launcher built from the intended checkout.

```powershell
$Launcher = (Resolve-Path -LiteralPath (Read-Host 'Actual launcher exe')).Path
$Boot = (Resolve-Path -LiteralPath (Read-Host 'Matched boot directory')).Path
$Bus = (Resolve-Path -LiteralPath (Read-Host 'Matched sibling_bus.ko')).Path
$Diag = (Resolve-Path -LiteralPath (Read-Host 'Ordinary baseline hcs_shmem_diag.ko')).Path
$globalFlags = @('--debug', '--gcs', '--count', '2', '--parallel', '2')
$pairFlags = @('--security-hardware', '--root-fs-type', 'none',
    '--boot-files-path', $Boot, '--shared-memory-size', '1048576',
    '--sibling-bus-guest-module', $Bus, '--sibling-diode-uplink',
    '--sibling-interactive')

# M01: ordinary shared backing/diagnostic handshake, using the same matched v4 guest.
& $Launcher @globalFlags lcow @pairFlags --shared-memory-two-uvm-proof `
    --shared-memory-guest-module $Diag
```

Global flags belong **before** `lcow`; LCOW flags follow it. Optional global
`--cpus` and `--memory` specify CPUs and MiB, respectively. Complete traffic,
attach and stop checks below and let cleanup finish before another invocation:
the existing pipe names and VM IDs are shared across runs.

For the protected run, **omit** both ordinary diagnostic flags:

For opt-in page metadata exports, add
`--page-metadata-output C:\ahv-deploy\page-metadata-results` with an existing
local host directory. A fresh run gets isolated `diode` and `workload`
directories, mounted separately as `/run/page-metadata-results` before sealing.
The matched runtime must include `collect-page-metadata.sh`, staged read-only
and copied into `/run/dtb-exec` on both roles. From attach run
`./collect-page-metadata.sh /run/page-metadata-results` manually.
Results persist after shutdown; no automatic collection or generic share
permission is enabled. Requested-share failure fails startup.
Export supports ordinary/protected standalone Linux relayed-GCS pairs too.
Plan9 still connects directly to the host; this is debug/test-only, not a Plan9
relay, attestation or host-I/O isolation guarantee. Owned startup, appliances,
OpenShell and benchmarks remain unsupported.

The matched diagnostic kernel enables page owner with `page_owner=on`.
The collector preserves raw kpageflags, full available page_owner records/PFNs,
runtime context, statuses, timestamps and hashes. Optional missing evidence is
marked partial. Required failures retain partial evidence without COMPLETE.
These are unsigned guest observations, not confidential/attested results;
export and collection perturb allocations and use the existing host-management
path. Compare only within the same VM incarnation and account for PFN reuse.
Allocation stacks do not prove sharing cause, and early stacks can be incomplete.

```powershell
# M02-M04: protected backing, neither partition mask selected.
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory
```

Protected mode requires all the pair settings above, including `--gcs`.
It rejects explicitly supplied ordinary diagnostic/two-proof flags even when
given false values, and rejects `--exec`, external mounts/shares, `--no-verity-boot`
and other unsupported route options. Do not copy the baseline's diagnostic
flags into a protected command. Protected-only masks/pause are rejected without
the opt-in. The launcher creates a fresh section and real VID controller;
`--shared-memory-name` is not accepted on this route.

### Combined workload root and GCS mediation

From a freshly rebuilt, complete matched runtime package:

```powershell
.\run.ps1 diode start -ProtectedShared -MediateGCS
.\run.ps1 attach diode
.\run.ps1 attach workload
.\run.ps1 diode stop
```

The public launcher selects exactly **32 MiB / 8192 pages**, the
new `hcs-shmem-snp-ahv-gcs-relay-root-idle-{halt,poll}.igvm` workload payload
in `sibling-root.vmgs`, and an internally generated single
`workload-root` read-only, non-removable LUN0 plan bound to the selected verified
root input. Native flags are `--protected-shared-memory --sibling-storage-root
--sibling-gcs-relay --sibling-storage-backends <plan>` with the normal SNP/GCS
pair settings. Never enable ordinary proof/marker flags. Missing relay images
or provider artifacts fail before native invocation; no installed ContainerPlat
files change. Use only the canonical `dist\runtime` / `dist\runtime.zip` output,
including matched `diode_storvsp.ko`, rootfs, GCS, AHV tool/hook and new
attestation relay-root images; consumers
need no source checkout. Historical baseline packages are insufficient.

The diode retains its direct RP root and host GCS. The workload has no direct
RP root attachment; its owned bundle root copy is attached read-only to the
diode and exported over sibling storage. Workload GCS control and stdio use
CID4 through the diode, without direct fallback. Protection applies to peer
backing, including storage transfer buffers; diode/host disk I/O and the
provider's separate bounce buffers are unchanged.

Diode Bootstrap receipt/lease validation precedes workload Import creation.
Early foreground-owned diode bootstrap/provider/relay setup overlaps workload
native startup without workload GCS/IP dependencies. ConfigureGCSRelay precedes
workload Start; handshake plus Import receipt and explicit relay readiness
precede network setup and required backing admission sealing.
After diode tool staging and BEFORE workload Start, the pair creates a separate
foreground `/run/dtb-exec/ahv-guest-ctl boot-server` through its owned service
list, not behind the relay's terminal `exec /bin/gcs`. Process creation is not
socket readiness: bounded transient CID4 setup retries may overlap workload
native boot. No peer/GCS readiness wait precedes workload Start.

Only this combined protected workload image carries measured `AHV_BOOT_ATTEST=1`.
The public debug-only `-LateAhvAttestation` switch instead selects the existing
unmarked relay-root image; backing/VMBus/root/GCS and the owned diode server
still start normally. After attaching the workload, manually run
`/usr/bin/ahv-guest-ctl boot-client` once. The same protocol, 300-second budget
and fresh private output rules apply. Workload progress goes to its shell;
diode phase/ioctl diagnostics stream to the launcher. Failure is a command
error, not a boot gate in this mode. No repeated-fetch/reset support is added.
Reports now describe post-boot/seal state; selected diode policies may require
the existing pre-seal `prepare` procedure, never weakening seals. Default
early behavior remains unchanged.

After read-only dm-verity root mount, its conditional `/startup.sh` hook invokes
the root-embedded `/usr/bin/ahv-guest-ctl boot-client` before the exact original
`/init`/GCS launch suffix and deny-policy flags. `/init` and runc are preserved.
There is no new public switch, post-GCS client delivery, new initramfs or kernel
device gate. Early device discovery is allowed. AF_VSOCK port 40500 connects
workload CID3 to diode CID4 only, never RP CID2 or IP fallback.

One fresh nonce and one monotonic **300-second** budget, starting before entropy,
cover collection/transfer/publication. The diode freezes all deduplicated current
ProtectedShared peers across the complete SELF inventory: any Pending/Installed/
Removing registration includes a peer; only all-Removed history is excluded.
Require at least one peer and every report; no first-match, GPA-equality or
single-backing selection. Missing/bad/late evidence fails boot before original
init/GCS, without a partial success marker or recovery shell. Exact AHVF bytes
and UNVERIFIED metadata publish atomically/freshly at `/ahv-attestation/current`
on workload-private 0700, 72-MiB nodev/nosuid/noexec tmpfs, surviving later
`/init` and its `/run`/`/tmp` mounts. Stale current evidence is never overwritten.
Structure/nonce/subject consistency is not signature, attachment-hash, trusted
identity or policy verification; no SNP evidence operation is added. Sequential
reports are not an atomic snapshot or final seal/device-state assertion.

The selected workload uses a validated seven-minute per-call native/GCS timeout,
sharing the ordinary `UtilityVM.Start` core. Combined setup gets ten minutes.
Diode/other Start callers retain the existing default (normally two minutes),
legacy pair setup five minutes, and seal/cleanup budgets remain independent.
No process-global timeout is changed. Premature server exit cancels startup,
including during workload GCS wait; ordinary successful collection does not
terminate the daemon. Cancellation joins server creation/Wait borrowers.
Shutdown joins workload users and terminates/waits for the workload before
joining/quiescing the diode service and releasing the root attachment through
live direct diode GCS. Only then can diode termination and participant-gated
teardown/reclaim complete. Uncertain drain/release retains owners and the
workload bundle root copy; it is not successful cleanup.

Rebuild a fresh complete canonical package with version-3 root metadata binding
tool/startup/root/image hashes; the root/hook/tool/images change measurements.
Do not mix old payloads or treat historical package hashes as current evidence.
External acceptance on matched SNP hardware must record pre-GCS publication,
later artifact reads, root/GCS continuity, absent/failing server, incomplete
batch, cancellation and full-budget behavior, plus confirmed borrower/provider/
native drainage before backing release. Source and callback/stream fixtures
cannot establish this. Other profiles still use manual AHV diagnostics.

Legacy public `-ProtectedShared` keeps its 2-MiB default and direct roots/GCS;
raw legacy geometry bounds are unchanged. Root-only/relay-only protection,
custom exports and appliance/OpenShell/benchmark modes are unsupported.
`-NoStorageMediation` is redundant for legacy and rejected with combined mode.
Initial hardware acceptance uses **no optional partition masks or pause**;
admission sealing still applies. Attach readiness does not establish completed
seals. This profile's hardware acceptance remains pending; no optional-category
effect or production isolation claim follows from source or fixtures.

Expected legacy direct-root source sequence (the combined ordering is above;
collect actual evidence, as logs alone are not proof):

1. `uvmboot-0`, diode/A (log role `a`), is configured
   `ProtectedShared=true`, `HiddenFromGuest=false`,
   `ProtectedSharedBackingMode="Bootstrap"`, expected lease zero.
   Native startup prepares, initializes in checked batches of at most four
   pages, completes RP CPU-access revocation, then installs.
2. Only after diode startup reports installed, fully initialized backing does
   the launcher create/start `uvmboot-1`, workload/B (log role `b`), with
   `ProtectedSharedBackingMode="Import"` and the actual observed nonzero lease.
   Both carry the same controller capability and section identity. Import
   references section rights/object/full-range metadata but creates no content
   view, secure view, probe, pin, replacement backing or second initialization.
3. DynMem's synchronous `PowerOnHandler` -> `MapAllRegions` completes protected
   setup; HCS successful worker start precedes started notification, and
   `OfferLink` checks installed identity/geometry before advertising access.
   Each guest receives its **own** GPA; equality is not required.
4. No pair/network wait precedes workload startup. Native backing setup needs
   neither GCS nor a guest command. GCS remains the host-management/tool/attach
   channel afterward; it is not replaced by this backing.
5. After both starts, checked module/discovery/CID/socket/interface/route/DNS,
   uplink/carrier/NAT and required service-listener checks complete. Workload
   is `10.200.0.2/30` on `dvsc0`, via diode `10.200.0.1/30` on `dvsp0`;
   only diode has the RP uplink. The uplink's name is discovered, not hardcoded.
   The launcher then seals page admission **once per backing page**, not once
   per VM, and optionally pauses and seals selected partitions.

Inspect the existing
`/sys/bus/vmbus/drivers/sibling_bus/*-*/sibling_instance` discovery output for
the single configured link in each guest. Its fields are
`bus_id`, `local_cid`, `peer_cid`, `version`, and `ready`: expect diode
`local_cid=4 peer_cid=3`, workload `local_cid=3 peer_cid=4`, and
`version=4 ready=1` on both, for ordinary and protected runs. This `version`
is the transport version, not descriptor version 2. Record each actual `bus_id`;
do not assume the two bus IDs are equal. These are the existing launcher
discovery/CID checks
(`siblingInstanceDiscoveryCommand` and `siblingVsockReadyCommand`), not a new
readiness tool or a substitute for the checked socket/network setup.

The URI in `ProtectedSharedControllerUri` is an operation-resource selector,
not authority. Real controller handles are attached through HCS operation
resources; operations own native duplicates through completion while the pair
retains its originals. No hidden old-proof fallback or import-to-bootstrap
fallback exists. Successful Install has local `Installed=true` with
`NativeResultValid=false` (the properties expose this validity as
`OperationResultValid`); strict decoding must not invent a native Install
receipt. `InitializedPages` survives as initialization **history**, not live
HV inventory, participant drainage, or reclaim/scrub proof.

The required boundary is RP denial before dependent guest use and installed
mapping before offer/use, **not** before the first guest instruction.
Metadata-only attachment after page seal may succeed; actual Install still
faces HV page/partition admission. VID participant counts are not that inventory.

### Retained history and bounded root-pool recovery

The native history/root-pool change (plan 000027) retains **eight registration
episodes per protected physical page/lifetime**, counting Pending, Installed,
Removing and Removed records. This is **not eight concurrent VMs**. Records are
not evicted or recycled to admit another episode. A ninth episode fails with
`HV_STATUS_INSUFFICIENT_BUFFERS`; capacity exhaustion does not prevent existing
lifetimes from being sealed, removed, reported or reclaimed. The published
report maximum remains **64 registrations**, with unchanged versions/layouts,
actual registration count and variable record length. The internal collection
scratch remains **2584 bytes**; it does not serialize unused slots.

The root pool funds hypervisor bookkeeping charged to the root partition. It
is not Windows free RAM, guest RAM or the pinned protected backing. A deposit
transfers **real physical pages**, not a counter/configuration setting.
Only Initialize returning exactly `STATUS_HV_INSUFFICIENT_ROOT_MEMORY` with
validated progress and an unfinished suffix can trigger this recovery:

1. The entire SVC/SK call returns, including release of fallback resources.
   Normal-kernel VID records each completed prefix in its lease ledger and
   aggregate result **once**, before considering a deposit.
2. At PASSIVE_LEVEL, with lease serialization and lease/pin/device owners
   retained but no partition/VSMM locks, VID invokes the existing exported
   `WinHvLowMemoryPolicyAutoDeposit` for `HV_PARTITION_ID_SELF`, not the child.
3. Policy success permits another SVC call on **only the unfinished zero-ID
   descriptor suffix**. Completed lifetimes are not reinitialized.
   There are at most **three policy invocations per original bounded request**
   (startup batches are at most four 4-KiB pages), even when retries make
   progress. This bounds retries, not the wall time of an executing kernel call.

Policy success is **not Initialize success**. Deposit failure or budget
exhaustion returns the last actual SVC status and aggregate completed prefix,
not the policy status or invented success. Malformed progress remains sticky
uncertainty and fails closed: it does not authorize backing access, unpinning,
ordinary fallback or a cleanup-success claim. The SK fallback path still makes
**no deposit**. No new API, ABI, CLI switch or reserve is introduced.
Child-memory shortages, contiguous/mirroring variants, `NO_RESOURCES`, history
exhaustion, busy, denied and other errors do not qualify; Seal, BeginTeardown,
Reclaim and other operations gain no recovery.

The existing policy requests **1088 pages / 4.25 MiB** per invocation, but can
permit retry after a nonzero partial deposit. Concurrent consumers can use the
shared pool immediately: neither that amount nor allocation success is
guaranteed. Deposits are not a private lease reserve and are not withdrawn when
the request or lease finishes.

The previous 8192-page reproduction propagated `0xC0350073` through
`MemoryManager.cpp:7839` and `SharedRegionManager.cpp:525`; it did **not** reach
the workload or relay. Zero cached counters did not prove zero native progress.
Neither that trace nor successful recovery proves the per-page entry allocator
was uniquely responsible. Preserve the 32-MiB combined geometry, required
backing admission sealing, root/GCS routing and diode-only AHV tooling above;
do not enable ordinary backing or relax receipt checks to obtain a boot.
Native build, matched deployment and hardware recovery remain pending; use
section 9's T1-T6 handoff rather than treating source acceptance as execution.

### Reduced containerd-owned Linux profile

Use the newly built matched shim and launcher from this worktree pair, not
only the historical integration pins above. From the complete companion runtime,
after stopping any existing pair, use a fresh state directory:

```powershell
.\run.ps1 diode start -ProtectedShared -MediateGCS -WorkloadPartitionSealMask 0x1 -LateAhvAttestation -StateDirectory .\runtime-owned\
.\run.ps1 container hello-world -StateDirectory .\runtime-owned\
.\run.ps1 container hello-world -StateDirectory .\runtime-owned\
.\run.ps1 attach workload
# Workload shell: /usr/bin/ahv-guest-ctl boot-client (once).
.\run.ps1 diode status -StateDirectory .\runtime-owned\
.\run.ps1 diode stop -StateDirectory .\runtime-owned\
```

`StateDirectory` or `CrictlPath` explicitly selects containerd ownership.
Only Linux with both root/GCS mediation, 32 MiB backing and unchanged SNP/
dm-verity/prototype policy is admitted. No owned seal pause, Unikraft,
OpenShell, tuning/CPU groups, static custom exports, direct workload root/GCS
or page-metadata host export. Preparation requires only sibling bus, storage
and network providers, iptables and the AHV tool, not benchmark/covert tools.
Standalone tool staging, masks and optional pause remain unchanged.

The same concrete `internal/sibling/protected_memory.go` backing/controller
is used by standalone and owned startup. Owned Bootstrap-before-Import,
root/GCS service overlap, readiness and required backing admission sealing
precede selected diode then workload partition seals. Backing admission sealing
is distinct from a partition mask. Omission makes no call; zero and all uint64
bits remain exact optional decimal strings. Seals finish before sandbox
infrastructure or application containers are created. Post-seal containers
and late AHV with `0x1` remain **pending hardware acceptance**: report native/
guest errors, never weaken masks or move sealing.

Early mode uses the measured AHV relay-root image. `LateAhvAttestation` selects
the unmarked relay-root image during preparation only; it is not a shim flag.
The owned diode collector is `/run/sibling-exec/ahv-guest-ctl`, while the
workload client is `/usr/bin/ahv-guest-ctl` from its verified root. Invoke late
client once; no repeated-fetch/reset or new evidence-verification policy exists.
AHV output remains unverified evidence. `protected-pair.log`, beside the
receipt, correlates guest/service diagnostics with run/VM IDs; ordinary CRI
logs and binary-logger support are unchanged. External logger completion is
not a native reclaim prerequisite.

Existing `owner.json` records protected selection, the fresh session's run ID,
expected receipt path, dispatch and sandbox reconciliation. Protected CRI
timeouts are `runp` 30 minutes and `stopp`/`rmp` 3 minutes; ordinary values
remain unchanged. The shim publishes only one terminal file, atomically and
without overwrite, after actual successful pair cleanup:

```json
{"version":1,"run_id":"<session>","workload_vm_id":"<sandbox>@vm","diode_vm_id":"<sandbox>@vm-diode","result":"released"}
```

It lives at `<fresh-session>\protected-cleanup-result.json`, with no mirrored
phase/counter/history protocol. It communicates completion, not attestation
or independent native authority. After dispatch, the runner requires sandbox
reconciliation **and** this exact matching result before terminating its
verified private daemon. Lost `runp` replies may use the existing owner label;
unknown sandbox, empty list, lost reply, daemon exit or `rmp` success alone
cannot authorize stop. Missing/malformed/mismatched completion retains daemon,
boot copies and diagnostics with `cleanup-incomplete` and an explicit manual
intervention error. Receipt publication failure never replays native controls;
reconciled removal is persisted so a later stop only checks completion.
Before dispatch, its own daemon may be closed normally. No forced shim kill,
service change, crash recovery or uncertain-work replay is provided.
Builds, regressions and H1-H3 hardware acceptance remain pending.

## 3. Attach, capture and filter actual workload traffic

From separate elevated Windows consoles, using the same actual launcher:

```powershell
& $Launcher attach diode
& $Launcher attach workload
# Use a third console to request pair shutdown, including during a pause:
& $Launcher stop
```

Run each attach command in its own console. Shells start in `/run/dtb-exec`.
Protected staging checks copies into executable tmpfs: `dtb` is
`diode_tcpbulk`, `vsock-test` is `diode_vsock_test`, `ipf` is `diode_iperf`,
and `tcpdump`, `tc`, `ipt`, `covert`, `demo.sh` are staged aliases. The iptables
multi-call syntax is `./ipt iptables ...`, not `./ipt ...`.
`ahv-guest-ctl` is shared read-only and copied/chmodded into this tmpfs **only
for the diode**; shares remain VM-owned through cleanup. Staging itself never
invokes `prepare` or collection. Combined mode then starts the owned boot-server;
its workload boot-client is already in the verified root, not staged via GCS.

In the **diode** shell, inspect the pre-NAT workload interface and rules:

```sh
ip -4 addr show dev dvsp0
ip route
./ipt iptables -w -t nat -L POSTROUTING -n -v
./ipt iptables -w -L FORWARD -n -v --line-numbers
./demo.sh -dump
```

`-dump` executes `tcpdump -i dvsp0 -n -l`; Ctrl-C stops capture, not the pair.
For a bounded filtered capture use, for example,
`./tcpdump -i dvsp0 -n -c 20 'host 10.200.0.2'` (it waits for 20 packets).
Traffic to diode's local sink is a link check, **not** a forwarded filtering
test. In the **workload** shell:

```sh
ip -4 addr show dev dvsc0
ip route show default
ping -c 2 -W 2 10.200.0.1
./dtb send 10.200.0.1 5001 1
# Choose an authorized, reachable lab IPv4 HTTP server and its actual TCP port.
printf 'Lab HTTP server IPv4: '; read -r LAB_IP
printf 'Lab HTTP server TCP port: '; read -r LAB_PORT
./dtb connect "$LAB_IP" "$LAB_PORT"
```

`dtb send` counts MiB; `dtb connect` sends `HEAD / HTTP/1.0` and expects a
response. Use a known compatible lab HTTP service, not an invented Internet
endpoint or this host's unrelated test port. Record its address/port and
successful unblocked response first. In a diode shell set `LAB_IP` to that same
actual destination, then:

```sh
printf 'Same lab destination IPv4: '; read -r LAB_IP
./demo.sh -block "$LAB_IP"
./ipt iptables -w -L FORWARD -n -v --line-numbers
# Repeat dtb connect from workload; record failure and matching DROP counters.
./demo.sh -unblock "$LAB_IP"
./ipt iptables -w -L FORWARD -n -v --line-numbers
# Repeat from workload; record restored response.
```

Run each phase separately; inspect counters/capture while generating traffic.
Block inserts a destination DROP in FORWARD; unblock deletes one matching rule.
Avoid duplicate block commands (one unblock does not remove all duplicates).
Pre-NAT capture may still see dropped packets; receipt there does not prove
egress. Record external server observations where available. Repeat before
partition calls using the pause, and after successful selected calls.
The pinned demo's `-covert`/`-smooth` use its hardcoded host destination; they
are not required here and must not be presented as a general timing-channel
or network-isolation proof.

## 4. Independent partition masks and pause

Each line below is a **separate run**, stopped and cleaned up before the next.
Omission makes no call; zero is an explicit call. Numeric examples demonstrate
forwarding, not approved policy bits or a promise native validation accepts them.

```powershell
# Neither: use the protected invocation above.
# Diode only.
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory `
    --diode-partition-seal-mask 1
# Workload only.
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory `
    --workload-partition-seal-mask 2
# Both, deliberately different.
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory `
    --diode-partition-seal-mask 1 --workload-partition-seal-mask 2
# Explicit zero and full-width/future bits: native rejection is a valid outcome.
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory `
    --diode-partition-seal-mask 0 `
    --workload-partition-seal-mask 18446744073709551615
```

If diode fails, the later workload call is unattempted: use a workload-only
run to observe a full-width workload mask independently. Malformed/overflow
values fail CLI parsing. No mask bits are locally filtered; the exact `uint64`
goes to `hcs:/VirtualMachine/SealPartition` as numeric `SealFlags`.

For a debugging pause, create a fresh evidence directory on an actual local
drive, then select at least one mask:

```powershell
$Evidence = Read-Host 'New absolute local-drive evidence directory'
New-Item -ItemType Directory -Path $Evidence -ErrorAction Stop | Out-Null
$Prefix = Join-Path (Get-Item -LiteralPath $Evidence).FullName 'partition-seal'
& $Launcher @globalFlags lcow @pairFlags --protected-shared-memory `
    --diode-partition-seal-mask 1 --workload-partition-seal-mask 2 `
    --partition-seal-pause-prefix $Prefix
```

Use an absolute local-drive prefix (not UNC). Both `<prefix>.ready` and
`<prefix>.resume` must be absent, including dangling links; never overwrite or
reuse either. This local-filesystem rendezvous is debugging, not authentication.
The owner acquires all attach/stop listeners before admission sealing/pause.
At publication checked networking and page admission sealing have completed,
and **no partition native call is in flight**.

In another PowerShell console, set `$Prefix` to the exact printed prefix.
The following bounded read opens with `FileShare.ReadWrite | Delete`. The
owner can publish a file while writing it: retry incomplete JSON, then inspect
the complete run, lease, UTC time, sealed-page count, selected roles/VM IDs and
exact hex masks against launcher output. Do not authorize a different run.

```powershell
$Prefix = Read-Host 'Exact current run pause prefix'
$ready = $null
$until = [DateTime]::UtcNow.AddSeconds(30)
do {
    $stream = $null; $reader = $null
    try {
        $sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream = [IO.File]::Open($Prefix + '.ready', [IO.FileMode]::Open,
            [IO.FileAccess]::Read, $sharing)
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8)
        $text = $reader.ReadToEnd()
        $candidate = ConvertFrom-Json -InputObject $text -ErrorAction Stop
        if ($candidate.run -and $candidate.ready_at_utc -and
            $candidate.lease -and $candidate.admission_sealed_pages -and
            @($candidate.partitions).Count -eq 2 -and
            $candidate.resume_exact_content -ceq "continue`n") {
            $ready = $candidate
        }
    } catch {
        # File not yet present or JSON not complete: bounded observation only.
        $ready = $null
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
    if ($null -eq $ready) { Start-Sleep -Milliseconds 100 }
} until ($null -ne $ready -or [DateTime]::UtcNow -ge $until)
if ($null -eq $ready) { throw 'No complete ready JSON; inspect launcher, do not resume.' }
$ready | ConvertTo-Json -Depth 6
```

For optional AHV preallocation (M3 below), attach the diode while this same run
is paused and run `./ahv-guest-ctl prepare` from `/run/dtb-exec`. Require exit
zero and `Prepared response capacity=0x200000` before authorizing resume.
If it fails, do not resume for the AHV scenario: preserve the error and stop.
Use actual approved diode/workload seal masks, not this section's numeric
forwarding examples. Preparation occurs after checked networking/backing page
admission sealing but before partition seals; never move or weaken those seals.

After inspecting identity and completing debugging/preparation, exclusively
create a new resume file. UTF-8 bytes must be **exactly** `continue` followed by LF: no BOM,
CR, or extras. `Set-Content` defaults are not this protocol.

```powershell
if ((Read-Host 'Type the inspected run ID to authorize resume') -cne $ready.run) {
    throw 'Run identity not confirmed.'
}
$resume = $null
try {
    $resume = [IO.File]::Open($Prefix + '.resume', [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes("continue`n")
    $resume.Write($bytes, 0, $bytes.Length)
    $resume.Flush()
} finally {
    if ($null -ne $resume) { $resume.Dispose() }
}
```

The temporary exclusive resume guard may briefly block `CreateNew` even after
the ready file appears. If it fails, do **not** overwrite/delete/retry blindly:
confirm the same run remains paused and the guard has closed, then manually
retry the exclusive creation a bounded number of times (for example within
five seconds). A real stale/foreign file is an error. Close the writer so the
owner can consume it. Ready/guard and successfully consumed resume objects are
deleted by their owner's retained handles. An invalid resume is retained and
fails the pause; preserve it as evidence, stop the run, use a fresh prefix.

Attach, protocol stop, Ctrl-C of the launcher, VM exit and service failure
remain live during pause. Stop/exit/cancellation prevents later uncommitted
calls; no hidden persistent seal-command server exists. Each selected seal has
a fresh five-minute budget **after** resume; pause time is excluded. Cleanup
has an independent two-minute budget. Deadlines cannot abandon already
executing synchronous native/GCS calls or release their borrowed owners.

Diode then workload are separate, non-atomic operations. Evidence records
omitted/pending/dispatched/completed/failed/uncertain/unattempted, exact decimal
and hex masks, run/VM identity and UTC attempt/return times. `dispatched` is
retrospective **submission-attempt** evidence, recorded before optional export
lookup: even missing `HcsSystemControl` can report dispatched. It is not proof
of native entry or effects. First failure/uncertainty skips later calls; earlier
success is not rolled back. Preserve individual results, never "atomic pair
success" or inferred unseal.

## 5. Manual diode AHV collection (M1-M4)

Use the complete canonical companion runtime (`artifacts\runtime-inputs` ->
`dist\runtime` / `dist\runtime.zip`) and matched HV/SK/VID/Linux artifacts.
The existing source staging, static CLI builder and manifest packaging carry
the tool; do not make a separate package or copy mismatched binaries into one.
Manual diagnostic validation remains in plan 000025 S6; compilation/tests for
the early protected boot integration are deferred to plan 000029 S5.
All `C:\os\src` builds remain manual operator work.

From the diode's `/run/dtb-exec`, invoke `./ahv-guest-ctl` with these forms
(angle brackets are operator inputs, brackets denote optional arguments):

```text
ahv-guest-ctl self --nonce <u64> --report <file> [--wbcl <file>]
ahv-guest-ctl dump-peers <report-file>
ahv-guest-ctl target --partition-id <u64> --nonce <u64> --report <file> [--wbcl <file>]
ahv-guest-ctl prepare
```

Perform the three steps separately. For example, enter two distinct fresh
caller-chosen unsigned 64-bit nonces and copy an explicit candidate ID after
inspecting the dump:

```sh
cd /run/dtb-exec
printf 'Fresh self nonce (u64): '; read -r SELF_NONCE
./ahv-guest-ctl self --nonce "$SELF_NONCE" --report /tmp/diode.ahvf --wbcl /tmp/diode.wbcl
# Continue only after success; this dump is offline and opens no AHV device.
./ahv-guest-ctl dump-peers /tmp/diode.ahvf
printf 'Explicit selected partition ID (u64): '; read -r SUBJECT_ID
printf 'Different fresh target nonce (u64): '; read -r TARGET_NONCE
./ahv-guest-ctl target --partition-id "$SUBJECT_ID" --nonce "$TARGET_NONCE" --report /tmp/workload.ahvf --wbcl /tmp/workload.wbcl
```

Inspect each exit/status before continuing; use distinct output paths for each
attempt so stale files are not mistaken for new evidence. IDs/nonces accept
full-width decimal or `0x` hex; do not truncate them. A peer-table index, vSock
CID or VM GUID is not a numeric partition ID. TARGET rejects SELF/NONE sentinels.
The selector supports live root-direct VM subjects, not root-as-third-party or
nested targeting; sharing is not an authorization condition on this prototype.
The dump shows each protected peer once under `not yet attached`, `attached`,
or `removed`, not an automatic selection. Any Installed/Removing registration
places it in `attached`; otherwise Pending takes precedence over Removed
history. Subject and communication-only IDs are excluded. Empty groups show
`(none)` and must not trigger a fallback.

The groups summarize retained peer registration states, not verified current
whole-link coverage or identity. The report still retains all per-page
lifetimes, aliases and removed/historical registrations, including historical-only
subject participation; those details are not printed by `dump-peers`.
`LifetimeId` names a backing-page lifetime, not a whole group/section.
Registration-local peer GPAs need not equal diode GPAs.

All claims, nonce equality and target-ID equality are **UNVERIFIED structural
diagnostics**, not signature/attachment-hash/expected-identity verification.
SELF has no independently authenticated expected identity. No trusted/ready/
isolated verdict, whole-region coverage/exclusivity policy, forwarding gate or
key release follows. Raw root-VTL0 WBCL is separate, unsigned and not an AHVF
attachment; saving it does not authenticate it against TPM evidence.

Only the diode issues AHV ioctl requests and owns their input/response memory and
completion, including when the report describes the workload. The combined
workload client only receives reports, never opens the AHV device. Device presence
and staging are not attestation success and allocate no AHV response slot.
Outside combined protected boot, manual AHV failure is not an ordinary
startup/networking gate.

Normal allocation stays lazy. Where approved diode seals prevent later response
allocation/sharing/growth, use only the optional manual `prepare` in section 4's
existing ready/resume pause. It reserves the maximum 2-MiB (`0x200000`) slot,
survives CLI close and performs no attestation, evidence or firmware query.
Post-seal self/target reuse it without sharing growth. A failure is explicit:
never weaken seals, reopen workload sharing or fall back to workload pages.

Do not overlap collection with save/migration/HV replacement. Finish first;
after replacement rediscover via a new self report and explicitly reselect.
Numeric IDs are HV-instance selectors, not portable identities. No migration
guard, drain/remapping support or safe pending continuation is implemented.

Record actual observations separately from source expectations:

| AHV ID (plan 000025) | Manual check and required evidence |
| --- | --- |
| M1 | Matched legacy direct-root protected pair, cold workload SNP cache and no preceding workload AHV request: complete self/offline dump/explicit target flow. Record cold-cache evidence and root preparation of the selected workload, not just CLI success. Trace only diode-owned request/response buffers, access and completion; workload supplies none. Self discovery must not need acquisition of peer identity. |
| M2 | Safely exercise actual nonexistent/deleted targets, supported ways to reach unsupported subjects, large inventories/logs (including beyond the old slot), and allocation/preparation/native failures. Record errno, HV/outer/inner statuses, requester completion/resume and cleanup. Expect complete responses with bounded resize or explicit terminal limit/failure, no usable partial report or alternate-subject/legacy fallback. Do not add fault-injection seams; unsafe/unexercisable failures remain unverified. |
| M3 | Verify diode-only delivery and no workload AHV allocation; record actual approved masks, ready identity, successful `0x200000` preparation before guarded resume, persistence after CLI exit and post-seal self/target reuse without sharing growth. Preserve failures rather than relaxing the policy. |
| M4 | Matched current-ABI self works; ordinary and legacy direct-root protected startup/networking require no AHV request or preparation. Combined protected boot uses the mandatory early exchange above. Where available, explicitly request AHV on an unsupported host and verify failure without fallback while ordinary networking remains operational. |

These are pending hardware checks, not claims that U1-U3 fixtures or source
review establish firmware, cold-cache or sealing success. Preserve source/build/
deployed hashes, VM IDs, exact commands, nonces, selected IDs, artifacts,
timestamps, layered statuses and cleanup observations. Cases not safely
inducible remain explicitly unverified.

## 6. Stop, failure and conservative cleanup

Prefer `uvmboot stop` and wait for launcher completion. Ctrl-C, VM exit or a
required service failure also cancels forward work. Do not force-kill the
launcher just because a synchronous native call exceeds a nominal deadline.
Preserve evidence before intervention under the lab's recovery procedure.

The pair owns controller/backing, both VM attempts, boot copies, uplink and
CPU groups. Protected command use opts into `Cmd.JoinBackgroundOperations`:
stdin/cancellation Kill workers are joined; protected listeners, connections,
frame readers, shell handlers and services must finish borrowing VM/process
owners before release. This is the source contract, not observed shutdown proof.

Legacy direct-root cleanup closes/joins shells, sends BeginTeardown for the exact known initialized
prefix, attempts participant Remove, terminates VMs and observes exit/drain,
joins services, and explicitly reclaims through native participant gating.
Framed partial progress is consumed before errors and never replayed;
only recognized framed zero-progress reclaim contention is retried under the
cleanup deadline. Whole initialized-backing zero verification happens **only
after authorized full reclaim**, followed by resource/copy release. A cached
Remove/Installed/InitializedPages property is not drain or release authority.
Combined cleanup instead uses the workload-first dependency ordering above;
it must not tear down backing while the workload/provider still depends on it.

Unknown startup ownership, malformed progress, incomplete teardown/reclaim,
unjoined borrowers or failed scrub verification must remain errors. No
ordinary `Section.Close`, content read, marker seed or opportunistic unpin is
safe after bootstrap dispatch. In the final history, `lease` is the lease
identity; `initialized`, `sealed`, `teardown`, and `reclaimed` are contiguous
prefix counts in **4-KiB pages**, not bytes; `zero-verified-bytes` counts
verified **bytes**; and `unknown` is a boolean uncertainty flag.
Retained owners are **in-process only**: launcher exit/native fallback cleanup
determine actual lifetime, not a persistence promise. Record unresolved cleanup
as unresolved, not as zero work or successful reclamation.

For startup errors, first check exact artifacts, export/IID availability,
resource handle rights and version/framing diagnostics. Optional troubleshooting:
short bounded Hyper-V DynMem/Worker/VID/Compute ETW (verbose level 5, circular
256-MiB cap, stop in `finally`, decode with `tracerpt`) correlated with actual
VM IDs/times. Derive VID IOCTL values from the matched header, not stale numbers;
outer HRESULT or `STATUS_PENDING` alone is not final native status. An
`E_NOINTERFACE` warrants checking the complete generated proxy aggregate,
including worker inputs, before changing COM contracts. Targeted proxy
regeneration is recovery for confirmed malformed output, not a mandatory
permanent clean rebuild. Traces and successful links are not experiment proof.

## 7. S8: user-only build/deployment handoff

In a matched AMD64 FRE Razzle environment, with the established OS tools and
`SDXROOT` including `src`,
the user runs the plan's affected-subtree command:

```powershell
if (-not $env:SDXROOT) { throw 'A matched Razzle environment is required.' }
build -parent /dir "$env:SDXROOT\onecore\vm"
if ($LASTEXITCODE -ne 0) { throw 'Native build failed; stop before deployment.' }
```

Build the dependency graph and final consumers, not just changed libraries.
Relevant targets include SharedRegionManager, VSMM, Vid.sys/Vid.dll, vmwpmem,
VirtualMotherboard, vmwrkr, vmdynmem, HCS management, schema/IDL generation and
the full proxy aggregate. Preserve the local import interface and unchanged
ordinary ABI. Do not hand-generate schemas, proxy tables, or export files.
Deploy the complete matched product set using the lab process and record final
versions/hashes; no deployment command is invented here.

Use a provisioned Go toolchain satisfying `go.mod` (`go 1.26.3` at handoff).
The plan's Linux cross-build form, from the actual hcsshim checkout:

```bash
# User only; replace the output placeholder with a fresh explicit directory.
(
    cd internal/computecore &&
    GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" CGO_ENABLED=0 \
        go tool github.com/Microsoft/go-winio/tools/mkwinsyscall \
        -output zsyscall_windows.go computecore.go
) &&
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -mod=readonly -o '<fresh-output-directory>/uvmboot.exe' ./internal/tools/uvmboot
```

The generator runs for the **host**, not as a Windows executable on Linux.
Review its actual delta for unrelated changes. Windows can instead run
`go generate ./internal/computecore` with the host Windows toolchain, then use
the matched companion builder with an explicit checkout:

```powershell
$Hcs = (Resolve-Path -LiteralPath (Read-Host 'Actual hcsshim checkout root')).Path
$Companion = (Resolve-Path -LiteralPath (Read-Host 'Matched companion checkout root')).Path
$Output = Read-Host 'Fresh absolute output exe path'
Push-Location -LiteralPath $Hcs
try {
    go generate ./internal/computecore
    if ($LASTEXITCODE -ne 0) { throw 'Generation failed; stop.' }
} finally { Pop-Location }
& (Join-Path $Companion 'scripts/build-hcs-launcher.ps1') `
    -HcsshimPath $Hcs -OutputPath $Output
```

Verify the companion checkout is `protected-shared-hcs-v1-upstream-20261110`
with the current AHV changes, and record its actual revision and script/resolver
contents before use; the earlier integration pin alone lacks the replacement ABI.
Explicit `-HcsshimPath` wins over `.hcs_path`
and `HCS_PATH`; the resolver checks checkout
root and markers. The script builds `.\internal\tools\uvmboot` with
`GOOS=windows`, `GOARCH=amd64`, `CGO_ENABLED=0`, `-mod=readonly`; it does not do
generation. Its default output name is `target\hcs\uvmboot-shmem.exe`, but the
example selects a fresh explicit output. Do not let configuration silently
select another checkout.

Record actual Go version, generation/build commands/results, output path/hash,
native build results separately, then deployment and Windows hardware results.
Use the existing toolchain without dependency upgrades. A successful Go build
or fixture test is neither a native-build nor a Windows hardware execution pass.

## 8. Manual evidence checklist and remaining gaps

Leave actual results blank until observed. Repeat M04/M05 for intended accepted
masks, including filtering during pause and after calls. Record rejected masks
honestly rather than weakening native validation.

| ID | User observation / protected invariant | Actual result | Evidence paths, IDs, times |
| --- | --- | --- | --- |
| M01 | Ordinary baseline boots, traffic/capture/block/unblock/attach/stop remain functional | | |
| M02 | Diode alone acquires pins once; trusted RP revocation then Install precede workload creation; no GCS backing setup | | |
| M03 | Late workload import uses same controller/lease/full backing, no host content view/secure/probe/pin; own GPA; installed-before-offer; real transport works | | |
| M04 | Actual workload lab-destination traffic traverses diode; capture and DROP counters plus block/unblock response agree, before/after selected calls | | |
| M05 | Neither/either/both and distinct masks; exact zero/full-width values; fresh pause, identity, resume sharing/bytes; attach/stop/Ctrl-C/exit live; independent budgets/outcomes | | |
| M06 | Safe invalid identities/rights, premature/partial import, mode/hidden/ordinary combinations and malformed/overflow masks fail without fallback; native masks diagnosed; if existing lab tools permit, metadata post-seal attachment versus HV Install rejection | | |
| M07 | Feasible startup/network/import failure, peer exit and normal stop; no unsafe release, duplicate prefixes or stranded listeners; authorized reclaim/full scrub; safe races only where existing tools permit | | |
| M08 | Native and Go generation/build separately recorded; complete matched export/IID/schema/proxy/tool/boot provenance; bounded ordering/root-denial/import evidence attributable to actual binaries | | |

The `shared_memory_test.go` transport-v4 expectations now match the shared
launcher guard: accept v4 and reject older transports. These source-level
fixtures do not establish native generation/build, matched deployment, hardware
execution, malformed-response injection or exhaustive allocation/race/failure
coverage. The
launcher intentionally offers no CLI for arbitrary controller identities,
permission failures or a third participant. If existing safe lab tooling cannot
exercise an M06/M07 negative, mark that subcase unverified; do not add a proof
engine, fakes, production seams or a third-VM harness.

Filtering observations are not comprehensive network/DMA isolation or
attestation evidence. The combined profile relays workload GCS over the protected
peer backing; diode host-facing GCS, direct-host Plan9 and diode/host disk I/O
remain unchanged.
Root-inaccessible pages cannot transparently replace host-consumed VMBus/GCS buffers.
Save/restore, cloning, PHU/KSR, migration and arbitrary subranges are unsupported.

On failure: preserve exact command/artifacts/IDs/status/prefix evidence, stop
unsafe forward work, classify the affected contract, request a focused source
fix and independent review, then rebuild/regenerate affected matched products,
redeploy and manually recheck the failing case plus relevant ordinary/regression
cases. Keep Go/native build, deployment and runtime outcomes separate. Missing
or lab-unavailable observations stay pending; source acceptance cannot fill them.

## 9. History/root-pool recovery: manual T1-T6 handoff (plan 000027)

This is a manual validation specification, **not execution authorization**.
All native builds, matched-PDB observations, hardware runs and fault cases below
are **PENDING**. Plan 000027 S4 is the only compilation/runtime stage for this
change, after accepted source review, an approved isolated target with matched
HV/NTOS/SK symbols and separately authorized execution. No new compiled tests,
harness, test-only retry replica or production fault hook is part of this
handoff. Unsafe/unavailable subcases remain explicitly unverified; adding a
harness requires a separate decision.

### Matched products and recording

Reuse section 1's established matched-product lab process, not a new deployment
script or permission to reboot/replace host products. Record exact source
revisions, commands and exit statuses, AMD64 FRE configuration, tool versions,
products rebuilt/retained, running HV identity and matched PDB identities.
Keep object-output/signing-stage comparisons separate from exact final
binplaced/package/deployed hashes where no transform intervenes. Rebuilding
`runtime.zip` alone does **not** install the HV/VID fix; a VID restart alone
does not replace the running HV.

The current implementation shell has empty `SDXROOT` and no `windows-build`
helper; native builds remain a manual S4 handoff. In an approved matched AMD64
FRE Razzle shell, confirm the established command form/configuration before
using the plan's affected graphs and final consumers:

```powershell
# S4 only; not a command to run during documentation/source acceptance.
if (-not $env:SDXROOT) { throw 'A matched Razzle environment is required.' }
build -parent /dir "$env:SDXROOT\onecore\hv\hvx"
if ($LASTEXITCODE -ne 0) { throw 'Hypervisor build failed; stop before deployment.' }
build -parent /dir "$env:SDXROOT\onecore\vm"
if ($LASTEXITCODE -ne 0) { throw 'Virtualization stack build failed; stop before deployment.' }
```

Build final HV images and `Vid.sys`, not just the changed libraries. Confirm
the new policy reference links through the existing WinHv import; retain the
unchanged matched SK/WinHv products. Do not use standalone `cl`, install a
substitute toolchain or hand-edit generated exports/proxies to mask a mismatch.
Section 7's earlier startup-stack handoff does not establish this change's
native acceptance.

For each T1-T6 case use a fresh evidence directory under the companion's
`artifacts\evidence`. Record actual run/VM IDs, lease, original page range/count,
UTC times, layered statuses, native Bootstrap/Import/lifecycle receipts,
refill traces, debugger observations, exact fault scope/site and cleanup result.
Unsigned launcher/guest logs and cached counters are correlation aids, not
native ownership, drain or reclaim authority.

Use the existing short DynMem/Worker/VID/Compute ETW recipe: discover the actual
providers with `logman query providers`; capture only those providers, all
keywords at verbose level 5, with a fresh session/provider file and circular
256-MiB cap (`logman create trace ... -pf ... -f bincirc -max 256 -ets`).
Stop the same session in `finally`, check native exit codes, preserve ETL and
decode with `tracerpt`. Correlate actual VM IDs/times and refill/native receipts,
record lost events/buffers and start a fresh capture for each attempt. Derive
IOCTLs from the current matched `VidIoctl.h`; no stale constants or unfiltered
syscall breakpoints. A propagated error identifies a boundary, not uniquely
the inner allocator.

### Source-grounded observation points and fault limits

Resolve symbols/locals against the **actual matched build**; line ranges below
are source anchors at OS `515f2a4f900aec27dbae3ec75728b2cf051f5686`, not
turnkey debugger commands or stable addresses. Read-only observation also
requires the approved target and a small set of run-filtered conditional/
one-shot breakpoints; broad per-page stops distort timeouts and pool behavior.

| Point (OS-relative path) | Observe; do not manufacture |
| --- | --- |
| `onecore/vm/vid/sys/vsmm/VsmmProtectedShared.c`, `VsmmProtectedSharedpPages:193-198` | Actual returned SVC `status` and per-call `completed` prefix, after the entire call returns. Confirm PASSIVE_LEVEL, retained lease/pin/device ownership and no partition/VSMM locks. The supported user-only buffered WDM preprocessing/controller path supplies this context; do not infer it from a WDF `ExecutionLevelPassive` setting. |
| Same helper, `204-229` | Descriptors/lifetimes, `Lease->Initialized`, aggregate `*Processed`, `remaining` and `refillAttempts`: each validated prefix enters the ledger once before deposit, leaving only the unfinished suffix. `STATUS_DATA_ERROR` sets sticky `Lease->Uncertain`. |
| Same helper, `239-259` | Actual policy invocations 1-3 and `policyStatus`, followed by suffix SVC retries only after policy success. The scalar VID trace carries `Lease->LeaseId`, `Code`, original `Start`/`Count`, aggregate processed, attempts, actual SVC status and policy status, not native addresses or contents. |
| `onecore/vm/vid/sys/vsmm/VsmmSvc.c:2074-2090,2186-2248` | Status/count/reserved/full-success framing validation, zero-ID input requirements and transfer of real completed SPA/lifetime descriptors even on failure. Preserve earlier valid progress; never reinterpret malformed framing as zero ownership. |
| `onecore/hv/hvx/am/gpa/GpaProtectedShared.c`, `GpaReserveProtectedShared:791` | Entry allocation is a **candidate only** for verify-before-mutation fault-facility/debugger investigation. Verify actual control flow and selected allocator's side effects first; it is neither a preauthorized fault command nor the only possible failing allocator. |

Use only a verified existing safe fault facility or separately approved narrowly
conditional one-shot debugger intervention filtered to this run, **before**
the selected allocator/operation mutates allocation, lifetime, publication or
permissions. Never overwrite successful allocator returns or lifetime-transition
statuses after mutation. No arbitrary `.call`, manual registration-count edits,
forged receipts, raw protected-backing access, broad host exhaustion or
disruption of unrelated VMs is authorized. If a safe pre-mutation site cannot
be established, stop that subcase and record it unverified.

With matched HV symbols, resolve `MmRootCompartment` and record
`Stats.DepositedPageCount`, `Stats.FreePageCount`,
`Stats.MinRequiredFreePageCount` and `Stats.AllocatedReservedPageCount` before,
around refill and after the case. Inspect
`GlobalZone->GlobalZonePromoteSubPageAllocations` before assuming sub-page
packing. Record before/after matched-PDB
`sizeof(GPAP_PROTECTED_SHARED_ENTRY)` and
`sizeof(GPAP_PROTECTED_SHARED_REGISTRATION)`, not guessed type sizes.
Removing 56 AMD64 pointers saves **448 requested bytes per entry**, or
**3.5 MiB for 8192 entries**, before allocator rounding and separately allocated
registration objects; this is **not exact resident-memory savings**.
Counters describe the global root compartment, not a lease-exclusive balance.
Free sub-pages, reserves, NUMA placement and concurrent allocations prevent
exclusive before/after attribution or a guaranteed refill amount.

### Manual matrix: expectations are not results

Retain separate results/evidence for each subcase; do not mark a whole row
passed when an unsafe/unavailable subcase remains unverified.

| ID | Setup / scenario | Expected outcome and protected invariant | Required evidence | Status |
| --- | --- | --- | --- | --- |
| T1 | Review capacity/bounds and source ABI; obtain matched before/after HV PDB type sizes. Only if existing safe native tooling permits, drive eight real retained episodes and a ninth attempt on one lifetime. | Eight history pointers, including Removed; no eviction/recycling. Published maximum 64 and 2584-byte scratch unchanged; report uses actual count/length. Ninth returns `HV_STATUS_INSUFFICIENT_BUFFERS` without losing history or blocking existing seal/remove/report/reclaim. | Bounds/assertion and collector review, actual PDB identities/type sizes, real state/count/registration/lifetime observations and capacity status plus cleanup receipts. No fabricated count; unavailable boundary exercise stays unverified. | **PENDING** |
| T2 | Fresh matched legacy/combined backing without induced shortage; narrowly scope policy/helper observation to the run. | Successful Initialize makes no deposit-policy call; native receipts and normal startup remain correct. Recovery adds no normal-path preallocation tax. | Actual SVC statuses/prefixes, scoped policy invocation count zero, native startup receipts, IDs and bounded ETW. | **PENDING** |
| T3 | On the approved isolated target, induce one real pre-mutation root shortage before any page completes, only at a verified safe site. | Valid zero-prefix exact shortage causes one SELF policy invocation after full SVC/SK return; retry submits the original unfinished range. Only actual later SVC completion can yield a checked startup receipt. | Fault site/scope, status and zero prefix, returned-call/context observations, actual policy result, suffix range/lifetimes, native receipt and pool snapshots. | **PENDING** |
| T4 | Induce shortage on a later page of one real four-page request, before that page gains a lifetime; retain prior real descriptors. | Earlier SPA/lifetime identities survive unchanged, lease initialization/aggregate prefix advance once, and only the unfinished zero-ID suffix is retried. Cleanup owns every initialized page. | Per-attempt ranges/counts, before/after descriptors and ledger, policy attempts, aggregate receipt and authorized teardown/reclaim evidence. | **PENDING** |
| T5 | Source-review every classification/budget/framing branch. Safely exercise other statuses/operations, persistent root shortage with progress between refills, deposit failure and malformed framing only where an existing safe exercise permits. | No deposit for excluded statuses/operations, uncertainty or exhausted suffix. Maximum three policy invocations per original request; progress never resets budget. Policy failure/exhaustion preserves last actual SVC failure and aggregate prefix; malformed results retain sticky uncertainty/owners, never success or fallback. | Individual statuses/operations, attempts 1-3 and absence of a fourth policy call, policy result, SVC status/prefix, framing/uncertainty and retained-owner observations. Record each unsafe/unavailable subcase unverified. | **PENDING** |
| T6 | Fresh matched HV/VID and complete verified runtime. Cold combined 32-MiB boot and separate legacy direct-root/GCS boot; normal stop and supported startup cancellation in separately observed runs, without optional masks/pause. | Workload root and GCS work through diode in combined mode; legacy remains direct. Real Bootstrap/Import receipts, required backing admission sealing and native release/scrub are correct, or uncertainty remains explicit with owners retained. No ordinary fallback or reduced geometry. AHV ioctl collection stays diode-only; the root-embedded workload client receives its early batch before GCS. | Section 2's `.\run.ps1 diode start -ProtectedShared -MediateGCS`, separate attach consoles and `diode stop`; separate `diode start -ProtectedShared`/stop and supported cancellation commands actually used. Preserve early batch/output, root/GCS readiness, receipts, run/VM IDs, refill traces/ETL, native cleanup/release and exact deployed hashes. | **PENDING** |

A no-shortage boot does not prove recovery; a deposit does not prove Initialize.
Preserve failures and remaining coverage gaps for S4 rather than adjusting
history, geometry, seals, backing mode or ownership checks to obtain success.

## Command and contract source map

Paths are relative to the indicated checkout; symbols, not stale line numbers,
are the lookup anchors.

| Requirement | Source authority | Manual check |
| --- | --- | --- |
| Globals/position; ordinary baseline; direct boot and role/module names | hcsshim `internal/tools/uvmboot/main.go` flags; `lcow.go` Action, `createLCOWOptions`, `sharedMemoryProofRole`, `siblingNetModuleName`; `internal/vm/vmutils/constants.go` | M01/M08 |
| Default-off validation, sequential Bootstrap/Import and actual resources, installed history | hcsshim `protected_sibling.go`: `validateProtectedSiblingCLI`, `runProtectedSibling`, `start`; `internal/hcs/schema2/shared_memory_region.go`; `internal/uvm/shared_memory.go`: startup/receipt validation | M02/M03/M06 |
| Native import rights/ownership, immutable metadata, HV admission | OS `onecore/vm/inc/vid.h`, `vid/dll/src/vid.src`, `vid/inc/{VidDefs.h,VidIoctl.h}`, `vid/sys/vsmm/{VsmmProtectedShared,VsmmMemoryBlock,VsmmVaGpaRange}.c` | M03/M06/M07 |
| Worker owner/local IID, retained initialization; protected startup before offers | OS `onecore/vm/worker/memory/{MemoryBlock,MemoryManager}.cpp`, `worker/vmb/VmbComGuestMemoryAccess.cpp`, `proxy/idl/VmbServices.idl`, `common/shmem/SharedRegionManager.cpp`, `dv/dm/vdev/dll/DynMemDevice.cpp`, `compute/management/orchestration/VirtualMachine/VirtualMachineOrchestrator.cpp` | M02/M03/M08 |
| Checked network/services, staging aliases, interfaces/CIDs | hcsshim `protected_sibling.go`: `stageProtectedSiblingTools`, `protectedSiblingNetwork`, `checkSockets`, `startService`; `lcow.go` sibling helpers; `bench.go` iperf name | M04/M07 |
| Demo/tcpdump/iptables syntax, traffic units, descriptor v2/54/event-range limits, transport v4/sysfs/CIDs and socket CLI | matched companion `203341899db940bc4165507f0371a1eed10d5949`: `diagnostics/sibling-bus/{demo.sh,diode_tcpbulk.c,diode_vsock_test.c,sibling_bus.c}`; `mshv/include/hyperv/{sibling_link.h,sibling_wire.h}` (`sibling_link_validate`, `SIBLING_BUS_VERSION`, `sibling_instance_show`); hcsshim `lcow.go`: `siblingTransportVersion`, `siblingInstanceDiscoveryCommand` (shared ordinary/protected guard) | M01/M03/M04 |
| Exact masks and truthful submission evidence | hcsshim `protected_sibling.go`: `sealPartitions`, `reportSeal`; `internal/uvm/partition.go`, `internal/hcs/v2/system.go`, `internal/computecore/computecore.go` | M05/M06 |
| Exclusive marker sharing/content/cleanup and interactive lifetime | hcsshim `protected_sibling_pause.go`; `interactive.go`: protected server and `siblingShellSession`; `internal/cmd/cmd.go` opt-in joining | M05/M07 |
| Prefix accounting/authorized reclaim/no ordinary close | Standalone `internal/tools/uvmboot/protected_sibling.go`: `cleanup`; shared `internal/sibling/protected_memory.go`: `ProtectedBacking`, `controlBatch`, `advance`, `Release` (the former standalone memory file was removed) | M07 |
| Owned configuration, Bootstrap-before-Import, joined cleanup and one final receipt | hcsshim `internal/sibling/pair.go`: `Config`, `decodeConfig`; `protected_pair.go`: `start`, `close`, `publishReceipt`; companion `runtime/start-uvms.ps1`, `run-workload-container.ps1` | H1-H3 pending |
| Generation/build and explicit builder checkout | plan S8; hcsshim `go.mod`, computecore generator directive; matched companion `203341899db940bc4165507f0371a1eed10d5949`: `scripts/{build-hcs-launcher.ps1,resolve-build-root.py}` | M08 |
