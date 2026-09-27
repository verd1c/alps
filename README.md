# ALPS: Android LPE Suite

## What is this?

ALPS is a tool very similar to [portbuster1337/lpe-toolkit](https://github.com/portbuster1337/lpe-toolkit), but for Android. It automatically collects and evaluates all required data and state of your device against a list of known local privilege escalation (LPE) vulnerabilities and determines which ones apply to your device and have a public exploit. It then allows you to choose and compile the exploit for your device which you can then use to gain temporary root privileges while keeping the bootloader locked and passing `Play Integrity` and `Key Attestation`.

<img width="1109" height="641" alt="image" src="https://github.com/user-attachments/assets/c6d9c9b9-b1bb-49dd-80a4-3bfc6e3d4127" />

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

## Quickstart

For the full functionality of ALPS, you will need both an on-device binary, and a host-side binary:
- **Collector (on-device):** gather on-device information.
- **Runner (host-side):** compile exploits and control the collector end-to-end.

### Device Build

To build the on-device binary with the rule KB embedded at build time:
```bash
cmake -B build/arm64 -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-26 \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release
cmake --build build/arm64

# push it to the device
adb push build/arm64/src/cli/alps /data/local/tmp/
adb shell 'chmod +x /data/local/tmp/alps && /data/local/tmp/alps scan'
```

This will allow a single binary build. If you need rule-KB development, `--rules <dir>` overrides the built-in KB with YAML files on disk.

### Host Build

The runner shells out to a few host tools. On Linux, macOS, or WSL:

```bash
cmake -B build/host -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/host
```

On Windows (Visual Studio 2022 Build Tools installed), the Android SDK already bundles CMake, Ninja, ADB, and the NDK. From a Developer PowerShell:

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

The host build produces `alps.exe` under `build/host/src/cli/`. 

### End-to-end run against a connected device

```powershell
# 1. Collect device facts using the on-device binary.
adb shell /data/local/tmp/alps collect > device_facts.json

# 2. One-shot prereq, fetch, build, deploy, run.
build\host\src\cli\alps.exe exploit go CVE-2022-38181 --i-am-authorized-to-test --facts device_facts.json --cleanup-after
```

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
