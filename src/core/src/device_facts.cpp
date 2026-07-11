#include "alps/core/device_facts.hpp"

#include <sstream>

using nlohmann::json;

namespace alps::core {

namespace {

    // nlohmann/json does not (de)serialize std::optional by default. We store
    // unset optionals as JSON null so downstream tools can tell "unknown" apart
    // from "empty string".
    template <typename T> void put_opt(json& j, const char* key, const std::optional<T>& v)
    {
        if (v.has_value()) {
            j[key] = *v;
        } else {
            j[key] = nullptr;
        }
    }

    template <typename T> void get_opt(const json& j, const char* key, std::optional<T>& v)
    {
        auto it = j.find(key);
        if (it == j.end() || it->is_null()) {
            v.reset();
        } else {
            v = it->get<T>();
        }
    }

} // namespace

void to_json(json& j, const Gpu& g)
{
    j = json::object();
    put_opt(j, "vendor", g.vendor);
    put_opt(j, "mali_arch", g.mali_arch);
    put_opt(j, "mali_driver", g.mali_driver);
    put_opt(j, "adreno_driver", g.adreno_driver);
    j["driver_blob_paths"] = g.driver_blob_paths;
}

void from_json(const json& j, Gpu& g)
{
    get_opt(j, "vendor", g.vendor);
    get_opt(j, "mali_arch", g.mali_arch);
    get_opt(j, "mali_driver", g.mali_driver);
    get_opt(j, "adreno_driver", g.adreno_driver);
    if (auto it = j.find("driver_blob_paths"); it != j.end() && it->is_object()) {
        g.driver_blob_paths = it->get<std::map<std::string, std::string>>();
    } else {
        g.driver_blob_paths.clear();
    }
}

void to_json(json& j, const DeviceFacts& f)
{
    j = json::object();
    put_opt(j, "android_release", f.android_release);
    put_opt(j, "sdk_int", f.sdk_int);
    put_opt(j, "spl", f.spl);
    put_opt(j, "vendor_spl", f.vendor_spl);
    put_opt(j, "build_fingerprint", f.build_fingerprint);
    put_opt(j, "manufacturer", f.manufacturer);
    put_opt(j, "model", f.model);
    put_opt(j, "device", f.device);
    put_opt(j, "kernel_version", f.kernel_version);
    put_opt(j, "soc_model", f.soc_model);
    put_opt(j, "soc_manufacturer", f.soc_manufacturer);
    j["abis"] = f.abis;
    j["gpu"] = f.gpu;
    put_opt(j, "selinux_mode", f.selinux_mode);
    put_opt(j, "bootloader_locked", f.bootloader_locked);
    put_opt(j, "rollback_index", f.rollback_index);
    put_opt(j, "verified_boot_state", f.verified_boot_state);
    put_opt(j, "mte_enabled", f.mte_enabled);
    put_opt(j, "treble_enabled", f.treble_enabled);
    put_opt(j, "dynamic_partitions", f.dynamic_partitions);
    put_opt(j, "collector_mode", f.collector_mode);
    put_opt(j, "collected_at", f.collected_at);
    put_opt(j, "root_indicator", f.root_indicator);
    j["raw_props"] = f.raw_props;
}

void from_json(const json& j, DeviceFacts& f)
{
    get_opt(j, "android_release", f.android_release);
    get_opt(j, "sdk_int", f.sdk_int);
    get_opt(j, "spl", f.spl);
    get_opt(j, "vendor_spl", f.vendor_spl);
    get_opt(j, "build_fingerprint", f.build_fingerprint);
    get_opt(j, "manufacturer", f.manufacturer);
    get_opt(j, "model", f.model);
    get_opt(j, "device", f.device);
    get_opt(j, "kernel_version", f.kernel_version);
    get_opt(j, "soc_model", f.soc_model);
    get_opt(j, "soc_manufacturer", f.soc_manufacturer);
    if (auto it = j.find("abis"); it != j.end() && it->is_array()) {
        f.abis = it->get<std::vector<std::string>>();
    } else {
        f.abis.clear();
    }
    if (auto it = j.find("gpu"); it != j.end() && !it->is_null()) {
        f.gpu = it->get<Gpu>();
    } else {
        f.gpu = Gpu {};
    }
    get_opt(j, "selinux_mode", f.selinux_mode);
    get_opt(j, "bootloader_locked", f.bootloader_locked);
    get_opt(j, "rollback_index", f.rollback_index);
    get_opt(j, "verified_boot_state", f.verified_boot_state);
    get_opt(j, "mte_enabled", f.mte_enabled);
    get_opt(j, "treble_enabled", f.treble_enabled);
    get_opt(j, "dynamic_partitions", f.dynamic_partitions);
    get_opt(j, "collector_mode", f.collector_mode);
    get_opt(j, "collected_at", f.collected_at);
    get_opt(j, "root_indicator", f.root_indicator);
    if (auto it = j.find("raw_props"); it != j.end() && it->is_object()) {
        f.raw_props = it->get<std::map<std::string, std::string>>();
    } else {
        f.raw_props.clear();
    }
}

DeviceFacts DeviceFacts::from_json_str(const std::string& s)
{
    return json::parse(s).get<DeviceFacts>();
}

std::string DeviceFacts::to_json_str(bool pretty) const
{
    json j = *this;
    return pretty ? j.dump(2) : j.dump();
}

json DeviceFacts::get_field(const std::string& dotted_path) const
{
    // Uniform access via JSON. The engine may cache the serialized form
    // per fact sheet; for now, correctness beats micro-perf.
    json root = *this;
    if (dotted_path.empty()) {
        return root;
    }

    const json* cur = &root;
    std::string segment;
    std::istringstream ss(dotted_path);
    while (std::getline(ss, segment, '.')) {
        if (!cur->is_object()) {
            return json {};
        }
        auto it = cur->find(segment);
        if (it == cur->end()) {
            return json {};
        }
        cur = &(*it);
    }
    return *cur;
}

} // namespace alps::core
