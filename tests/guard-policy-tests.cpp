// Standalone Windows test. Production definitions are compiled into this TU so
// the real builder/comparator are exercised without adding a production ABI.
// The test never calls GuardConfigureV2, GuardRemove or a transaction commit.
#include "../native/guard.cpp"
#include <objbase.h>
#include <sddl.h>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <type_traits>
#pragma comment(lib, "ole32.lib")

namespace audit {
using Bytes = std::vector<unsigned char>;
static void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
static void check(DWORD error, const char* operation) {
    if (error) throw std::runtime_error(std::string(operation) + " failed, code=" + std::to_string(error));
}
template<class T> static void put(Bytes& bytes, const T& value) {
    const auto* begin = reinterpret_cast<const unsigned char*>(&value);
    bytes.insert(bytes.end(), begin, begin + sizeof(value));
}
static void blob(Bytes& bytes, const FWP_BYTE_BLOB& value) {
    put(bytes, value.size);
    if (value.size) {
        require(value.data != nullptr, "invalid blob in snapshot");
        bytes.insert(bytes.end(), value.data, value.data + value.size);
    }
}
static void optionalGuid(Bytes& bytes, const GUID* value) {
    put(bytes, value != nullptr); if (value) put(bytes, *value);
}
static void string(Bytes& bytes, const wchar_t* value) {
    put(bytes, value != nullptr);
    if (!value) return;
    size_t size = wcslen(value);
    put(bytes, size);
    for (size_t i = 0; i < size; i++) put(bytes, value[i]);
}
template<class V> static void value(Bytes& bytes, const V& v) {
    put(bytes, v.type);
    // These are all value types emitted by current and legacy ProxyBridge.
    // Refuse any unknown committed policy before starting a write transaction.
    switch (v.type) {
    case FWP_EMPTY: break;
    case FWP_UINT8: put(bytes, v.uint8); break;
    case FWP_UINT16: put(bytes, v.uint16); break;
    case FWP_UINT32: put(bytes, v.uint32); break;
    case FWP_UINT64:
        require(v.uint64 != nullptr, "invalid uint64 in snapshot"); put(bytes, *v.uint64); break;
    case FWP_BYTE_BLOB_TYPE:
        require(v.byteBlob != nullptr, "invalid blob pointer in snapshot"); blob(bytes, *v.byteBlob); break;
    case FWP_SECURITY_DESCRIPTOR_TYPE:
        require(v.sd != nullptr, "invalid security descriptor in snapshot"); blob(bytes, *v.sd); break;
    case FWP_BYTE_ARRAY16_TYPE:
        require(v.byteArray16 != nullptr, "invalid IPv6 address in snapshot");
        for (auto b : v.byteArray16->byteArray16) put(bytes, b);
        break;
    case FWP_V4_ADDR_MASK:
        if constexpr (std::is_same_v<V, FWP_CONDITION_VALUE0>) {
            require(v.v4AddrMask != nullptr, "invalid IPv4 mask in snapshot");
            put(bytes, v.v4AddrMask->addr); put(bytes, v.v4AddrMask->mask);
        } else throw std::runtime_error("address mask is invalid as a filter weight");
        break;
    case FWP_V6_ADDR_MASK:
        if constexpr (std::is_same_v<V, FWP_CONDITION_VALUE0>) {
            require(v.v6AddrMask != nullptr, "invalid IPv6 mask in snapshot");
            for (auto b : v.v6AddrMask->addr) put(bytes, b);
            put(bytes, v.v6AddrMask->prefixLength);
        } else throw std::runtime_error("address mask is invalid as a filter weight");
        break;
    default: throw std::runtime_error("unsupported policy value type; write transaction not permitted");
    }
}
static void display(Bytes& bytes, const FWPM_DISPLAY_DATA0& data) {
    string(bytes, data.name); string(bytes, data.description);
}
static Bytes snapshot(HANDLE engine) {
    Bytes result;
    FWPM_SUBLAYER0* layer = nullptr;
    DWORD error = FwpmSubLayerGetByKey0(engine, &sublayer, &layer);
    if (error == FWP_E_SUBLAYER_NOT_FOUND) put(result, false);
    else {
        check(error, "snapshot sublayer");
        try {
            put(result, true); put(result, layer->subLayerKey); display(result, layer->displayData);
            put(result, layer->flags); optionalGuid(result, layer->providerKey);
            blob(result, layer->providerData); put(result, layer->weight);
        } catch (...) { FwpmFreeMemory0(reinterpret_cast<void**>(&layer)); throw; }
        FwpmFreeMemory0(reinterpret_cast<void**>(&layer));
    }
    std::vector<UINT64> ids;
    check(ownFilters(engine, ids), "snapshot enumeration");
    std::sort(ids.begin(), ids.end()); put(result, ids.size());
    for (auto id : ids) {
        FWPM_FILTER0* f = nullptr;
        check(FwpmFilterGetById0(engine, id, &f), "snapshot filter");
        try {
            put(result, f->filterId); put(result, f->filterKey); display(result, f->displayData);
            put(result, f->flags); optionalGuid(result, f->providerKey); blob(result, f->providerData);
            put(result, f->layerKey); put(result, f->subLayerKey); value(result, f->weight);
            value(result, f->effectiveWeight); put(result, f->action.type); put(result, f->action.filterType);
            if (f->flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) put(result, f->providerContextKey);
            else put(result, f->rawContext);
            std::vector<Bytes> conditions;
            for (UINT32 i = 0; i < f->numFilterConditions; i++) {
                Bytes c;
                put(c, f->filterCondition[i].fieldKey); put(c, f->filterCondition[i].matchType);
                value(c, f->filterCondition[i].conditionValue); conditions.push_back(std::move(c));
            }
            std::sort(conditions.begin(), conditions.end()); put(result, conditions.size());
            for (const auto& c : conditions) { put(result, c.size()); result.insert(result.end(), c.begin(), c.end()); }
        } catch (...) { FwpmFreeMemory0(reinterpret_cast<void**>(&f)); throw; }
        FwpmFreeMemory0(reinterpret_cast<void**>(&f));
    }
    return result;
}
struct EngineHandle {
    HANDLE handle = nullptr;
    EngineHandle() { check(open(&handle), "open WFP"); }
    ~EngineHandle() { if (handle) FwpmEngineClose0(handle); }
};
struct AppLock {
    HANDLE handle = nullptr;
    AppLock() {
        handle = CreateMutexW(nullptr, FALSE, L"Global\\ProxyBridge-8CBA1041");
        if (!handle) check(GetLastError(), "open application mutex");
        DWORD wait = WaitForSingleObject(handle, 0);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
            CloseHandle(handle); handle = nullptr;
            throw std::runtime_error("application is active or application mutex unavailable; test refused");
        }
    }
    ~AppLock() { if (handle) { ReleaseMutex(handle); CloseHandle(handle); } }
};
struct RollbackOnly {
    HANDLE engine;
    bool active = false;
    explicit RollbackOnly(HANDLE h) : engine(h) {
        check(FwpmTransactionBegin0(engine, 0), "begin rollback-only transaction"); active = true;
    }
    void abort() {
        check(FwpmTransactionAbort0(engine), "abort rollback-only transaction"); active = false;
    }
    ~RollbackOnly() { if (active) FwpmTransactionAbort0(engine); }
};
static void install(HANDLE h, Policy& policy, UINT16 weight = 0xffff) {
    check(erase(h), "erase own test policy");
    DWORD error = FwpmSubLayerDeleteByKey0(h, &sublayer);
    if (error != FWP_E_SUBLAYER_NOT_FOUND) check(error, "replace own sublayer");
    FWPM_SUBLAYER0 layer{};
    layer.subLayerKey = sublayer; layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT; layer.weight = weight;
    layer.displayData.name = const_cast<wchar_t*>(L"ProxyBridge rollback-only audit");
    check(FwpmSubLayerAdd0(h, &layer, nullptr), "add own test sublayer");
    for (size_t i = 0; i < policy.rules.size(); i++) {
        auto f = filter(policy, i); check(FwpmFilterAdd0(h, &f, nullptr, nullptr), "add expected filter");
    }
}
static void expectMatch(HANDLE h, Policy& policy, bool expected) {
    bool actual = false;
    check(matchesPolicy(h, policy, actual), "production policy comparator");
    require(actual == expected, expected ? "valid policy was rejected" : "corrupted policy was accepted");
}
using Mutation = std::function<void(FWPM_FILTER0&, std::vector<FWPM_FILTER_CONDITION0>&, UINT64&)>;
static void replace(HANDLE h, Policy& policy, size_t index, const Mutation& mutate) {
    auto f = filter(policy, index);
    auto conditions = policy.rules[index].conditions;
    UINT64 weight = policy.rules[index].weight;
    f.filterCondition = conditions.data(); f.weight.uint64 = &weight;
    mutate(f, conditions, weight);
    f.filterCondition = conditions.data(); f.numFilterConditions = static_cast<UINT32>(conditions.size());
    auto id = f.filterKey; // V3 uses distinct key slots for persistent and active rules.
    check(FwpmFilterDeleteByKey0(h, &id), "delete filter for mutation");
    check(FwpmFilterAdd0(h, &f, nullptr, nullptr), "add mutated filter");
}
static size_t withCondition(Policy& policy, const GUID& field) {
    for (size_t i = 0; i < policy.rules.size(); i++)
        for (const auto& c : policy.rules[i].conditions) if (same(c.fieldKey, field)) return i;
    throw std::runtime_error("expected test condition missing");
}
static FWPM_FILTER_CONDITION0& condition(std::vector<FWPM_FILTER_CONDITION0>& conditions, const GUID& field) {
    for (auto& c : conditions) if (same(c.fieldKey, field)) return c;
    throw std::runtime_error("mutation condition missing");
}
static void pass(const char* name) { std::cout << "PASS: " << name << std::endl; }
static void dnsTests(HANDLE h, UINT32 ip, UINT16 port, UINT64 luid, const wchar_t* engine, const wchar_t* const* excluded) {
    auto dnsRule = [](const Rule& r) {
        return std::any_of(r.conditions.begin(), r.conditions.end(), [](const auto& c) { return same(c.fieldKey, FWPM_CONDITION_ALE_USER_ID); });
    };
    Policy blocked{}, empty{}, active{}, invalid{};
    check(build(blocked, ip, port, 0, engine, excluded, 1, true), "build stopped DNS policy");
    check(build(empty, ip, port, 0, engine, nullptr, 0, true), "build no-exclusion DNS request");
    check(build(active, ip, port, luid, engine, excluded, 1), "build active strict DNS policy");
    require(build(invalid, ip, port, luid, engine, excluded, 1, true) == ERROR_INVALID_PARAMETER, "active direct DNS request was accepted");
    require(std::none_of(empty.rules.begin(), empty.rules.end(), dnsRule) && std::none_of(active.rules.begin(), active.rules.end(), dnsRule), "shared DNS permit exists without stopped exclusions");
    pass("DNS permit absent for no exclusions and active TUN; incompatible active request rejected");
    std::vector<size_t> dns;
    for (size_t i = 0; i < blocked.rules.size(); i++) if (dnsRule(blocked.rules[i])) dns.push_back(i);
    require(dns.size() == blocked.dns.size() * 2, "DNS TCP/UDP endpoint coverage differs");
    BOOL present = FALSE, defaulted = FALSE; PACL acl = nullptr;
    require(IsValidSecurityDescriptor(blocked.dnsIdentity.data) != FALSE &&
        GetSecurityDescriptorDacl(blocked.dnsIdentity.data, &present, &acl, &defaulted) != FALSE && present && acl && acl->AceCount == 1,
        "DNS service descriptor must have exactly one explicit access ACE");
    void* rawAce = nullptr; require(GetAce(acl, 0, &rawAce) != FALSE, "read DNS service access ACE");
    auto ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
    require(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && ace->Mask == FWP_ACTRL_MATCH_FILTER, "DNS identity ACE has unexpected kind or rights");
    DWORD sidBytes = 0, domainChars = 0; SID_NAME_USE use{};
    LookupAccountNameW(nullptr, L"NT SERVICE\\Dnscache", nullptr, &sidBytes, nullptr, &domainChars, &use);
    require(GetLastError() == ERROR_INSUFFICIENT_BUFFER && sidBytes > 0, "resolve DNS service SID size");
    std::vector<BYTE> expectedSid(sidBytes); std::vector<wchar_t> domain(domainChars);
    require(LookupAccountNameW(nullptr, L"NT SERVICE\\Dnscache", expectedSid.data(), &sidBytes, domain.data(), &domainChars, &use) != FALSE &&
        EqualSid(expectedSid.data(), &ace->SidStart) != FALSE, "DNS descriptor grants an identity other than Dnscache");
    pass("DNS descriptor grants match rights only to the Dnscache service SID");
    for (size_t i : dns) {
        auto& r = blocked.rules[i]; auto& c = r.conditions;
        require(!r.active && r.slot >= 512 && r.slot < 1024 && r.action == FWP_ACTION_PERMIT && c.size() == 6,
            "DNS lifetime, key scope, action or mandatory condition count differs");
        require(same(r.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V4) || same(r.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6), "DNS is allowed on an inbound layer");
        require(condition(c, FWPM_CONDITION_ALE_APP_ID).conditionValue.byteBlob != nullptr, "DNS lacks application identity");
        require(condition(c, FWPM_CONDITION_ALE_USER_ID).conditionValue.type == FWP_SECURITY_DESCRIPTOR_TYPE, "DNS lacks service security descriptor");
        require(condition(c, FWPM_CONDITION_IP_REMOTE_PORT).conditionValue.uint16 == 53, "DNS allows a non-DNS port");
        auto protocol = condition(c, FWPM_CONDITION_IP_PROTOCOL).conditionValue.uint8;
        require(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP, "DNS allows an unsupported protocol");
        require(*condition(c, FWPM_CONDITION_IP_NEXTHOP_INTERFACE).conditionValue.uint64 != 0, "DNS permits an unspecified interface");
        require(std::all_of(c.begin(), c.end(), [](const auto& item) { return item.matchType == FWP_MATCH_EQUAL; }), "DNS uses a broad match type");
        (void)condition(c, FWPM_CONDITION_IP_REMOTE_ADDRESS);
    }
    install(h, blocked); expectMatch(h, blocked, true);
    pass("Windows accepts complete scoped stopped DNS policy and production comparator verifies it in rollback-only transaction");
    if (dns.empty()) {
        std::cout << "SKIP: DNS-specific mutations require at least one configured DNS endpoint on an Up non-TUN adapter" << std::endl;
        return;
    }
    size_t index = dns.front();
    auto negative = [&](const char* name, const Mutation& mutation) {
        replace(h, blocked, index, mutation); expectMatch(h, blocked, false);
        install(h, blocked); expectMatch(h, blocked, true); pass(name);
    };
    negative("DNS without service identity rejected instead of allowing every svchost", [](auto&, auto& c, auto&) {
        c.erase(std::remove_if(c.begin(), c.end(), [](const auto& item) { return same(item.fieldKey, FWPM_CONDITION_ALE_USER_ID); }), c.end());
    });
    negative("DNS without exact server address rejected", [](auto&, auto& c, auto&) {
        c.erase(std::remove_if(c.begin(), c.end(), [](const auto& item) { return same(item.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS); }), c.end());
    });
    negative("DNS wrong port rejected", [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_REMOTE_PORT).conditionValue.uint16 = 443; });
    negative("DNS wrong executable rejected", [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_ALE_APP_ID).conditionValue.byteBlob = blocked.apps[0]; });
    UINT64 wrongNic = *condition(blocked.rules[index].conditions, FWPM_CONDITION_IP_NEXTHOP_INTERFACE).conditionValue.uint64 + 1;
    negative("DNS wrong interface rejected", [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_NEXTHOP_INTERFACE).conditionValue.uint64 = &wrongNic; });
    PSECURITY_DESCRIPTOR everyone = nullptr; ULONG descriptorBytes = 0;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x1;;;WD)", SDDL_REVISION_1, &everyone, &descriptorBytes) != FALSE, "create negative DNS identity");
    FWP_BYTE_BLOB wrongIdentity{descriptorBytes, reinterpret_cast<UINT8*>(everyone)};
    try {
        negative("DNS broader service security descriptor rejected", [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_ALE_USER_ID).conditionValue.sd = &wrongIdentity; });
    } catch (...) { LocalFree(everyone); throw; }
    LocalFree(everyone);
    FWP_BYTE_ARRAY16 a{}, b{}; a.byteArray16[0] = b.byteArray16[0] = 0x20; a.byteArray16[1] = b.byteArray16[1] = 1;
    FWP_CONDITION_VALUE0 va{}, vb{}; va.type = vb.type = FWP_BYTE_ARRAY16_TYPE; va.byteArray16 = &a; vb.byteArray16 = &b;
    require(valueEqual(va, vb), "equal IPv6 condition values rejected");
    b.byteArray16[15] = 1; require(!valueEqual(va, vb), "different IPv6 condition values accepted");
    pass("IPv6 DNS address comparator distinguishes all 16 bytes");
    install(h, active); expectMatch(h, active, true); expectMatch(h, blocked, false);
    require(std::none_of(active.rules.begin(), active.rules.end(), dnsRule), "active policy retained stopped resolver");
    pass("replacing stopped DNS policy with active policy removes resolver permits within transaction");
}
static void run(HANDLE h, const wchar_t* engine, const wchar_t* alternate) {
    require(_wcsicmp(engine, alternate) != 0, "engine and alternate executable must differ");
    constexpr UINT32 ip = 0xc000020a; // Documentation address, no traffic is generated.
    constexpr UINT16 port = 1080;
    constexpr UINT64 luid = 0x0000000000010000ULL; // Synthetic; never a readiness claim.
    const wchar_t* excluded[] = { alternate };
    Policy policy{};
    check(build(policy, ip, port, luid, engine, excluded, 1), "build expected policy");
    size_t baselineCount = 0, activeCount = 0;
    std::vector<GUID> distinctKeys;
    for (size_t i = 0; i < policy.rules.size(); i++) {
        auto f = filter(policy, i);
        require(std::none_of(distinctKeys.begin(), distinctKeys.end(), [&](const GUID& k) { return same(k, f.filterKey); }), "persistent and active key scopes overlap");
        distinctKeys.push_back(f.filterKey);
        if (policy.rules[i].active) {
            activeCount++;
            require(f.flags == 0 && f.action.type == FWP_ACTION_PERMIT && policy.rules[i].slot >= 1024, "active permits are persistent or have wrong key scope");
        } else {
            baselineCount++;
            require(f.flags == FWPM_FILTER_FLAG_PERSISTENT && policy.rules[i].slot < 1024, "baseline lifetime or key scope is incorrect");
        }
    }
    require(baselineCount == 13 && activeCount == 10, "one-exclusion policy has unexpected baseline/active shape");
    pass("persistent baseline and nonpersistent active permit shapes use distinct keys; not a lifetime test");
    auto hasArrival = [](const Rule& rule) {
        return std::any_of(rule.conditions.begin(), rule.conditions.end(), [](const auto& c) { return same(c.fieldKey, FWPM_CONDITION_IP_ARRIVAL_INTERFACE); });
    };
    std::vector<size_t> returnRules;
    size_t outboundTunRules = 0;
    bool returnV4 = false, returnV6 = false;
    for (size_t i = 0; i < policy.rules.size(); i++) {
        auto& rule = policy.rules[i];
        if (hasArrival(rule)) {
            returnRules.push_back(i);
            require(rule.active && rule.action == FWP_ACTION_PERMIT && rule.weight == 100 && rule.conditions.size() == 2 && filter(policy, i).flags == 0,
                "TUN return permit must be dynamic and contain exactly arrival and reauthorization conditions");
            auto& arrival = condition(rule.conditions, FWPM_CONDITION_IP_ARRIVAL_INTERFACE);
            auto& flags = condition(rule.conditions, FWPM_CONDITION_FLAGS);
            require(arrival.matchType == FWP_MATCH_EQUAL && arrival.conditionValue.type == FWP_UINT64 &&
                arrival.conditionValue.uint64 && *arrival.conditionValue.uint64 == luid,
                "TUN return permit is not bound to the exact active LUID");
            require(flags.matchType == FWP_MATCH_FLAGS_ALL_SET && flags.conditionValue.type == FWP_UINT32 &&
                flags.conditionValue.uint32 == FWP_CONDITION_FLAG_IS_REAUTHORIZE,
                "TUN return permit does not require reauthorization");
            if (same(rule.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V4)) { require(!returnV4, "duplicate IPv4 TUN return permit"); returnV4 = true; }
            else if (same(rule.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6)) { require(!returnV6, "duplicate IPv6 TUN return permit"); returnV6 = true; }
            else throw std::runtime_error("TUN return permit is on an unexpected layer");
            // Empty arrival values are never an accepted substitute for a TUN
            // identity. Exercise the comparator without installing an invalid
            // condition type that Windows itself may reject first.
            auto expected = filter(policy, i), changed = expected;
            auto conditions = rule.conditions;
            auto& empty = condition(conditions, FWPM_CONDITION_IP_ARRIVAL_INTERFACE);
            empty.conditionValue = {}; empty.conditionValue.type = FWP_EMPTY;
            changed.filterCondition = conditions.data();
            require(!filterEqual(changed, expected), "Empty arrival interface was accepted");
        }
        for (const auto& c : rule.conditions) if (same(c.fieldKey, FWPM_CONDITION_IP_NEXTHOP_INTERFACE)) {
            require(rule.active && rule.action == FWP_ACTION_PERMIT && rule.conditions.size() == 1 &&
                c.matchType == FWP_MATCH_EQUAL && c.conditionValue.type == FWP_UINT64 && c.conditionValue.uint64 && *c.conditionValue.uint64 == luid &&
                (same(rule.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V4) || same(rule.layer, FWPM_LAYER_ALE_AUTH_CONNECT_V6)),
                "Initial outbound TUN authorization was weakened or replaced");
            ++outboundTunRules;
        }
    }
    require(returnRules.size() == 2 && returnV4 && returnV6 && outboundTunRules == 2,
        "Expected two return permits alongside two unchanged outbound TUN permits");
    pass("IPv4/IPv6 return permits require exact TUN arrival and reauthorization; outbound next-hop rules remain strict");
    for (bool dns : {false, true}) {
        Policy stopped{};
        check(build(stopped, ip, port, 0, engine, excluded, 1, dns), "build stopped return-policy regression");
        require(std::none_of(stopped.rules.begin(), stopped.rules.end(), hasArrival), "Stopped policy retains TUN return permits");
        require(std::none_of(stopped.rules.begin(), stopped.rules.end(), [](const auto& rule) { return rule.active; }), "Stopped policy retains an active permission");
    }
    Policy noExclusions{};
    check(build(noExclusions, ip, port, luid, engine, nullptr, 0), "build active policy without exclusions");
    require(std::count_if(noExclusions.rules.begin(), noExclusions.rules.end(), hasArrival) == 2 &&
        std::count_if(noExclusions.rules.begin(), noExclusions.rules.end(), [](const auto& rule) { return rule.active; }) == 6,
        "Active no-exclusions policy lacks the narrowly scoped TUN return pair");
    pass("TUN return permits are absent in both stopped modes and present without application exclusions");
    const Bytes before = snapshot(h); // Unsupported types fail before write transaction.
    RollbackOnly transaction(h);
    std::exception_ptr failure;
    GUID foreignLayer{}, foreignFilter{};
    try {
        check(CoCreateGuid(&foreignLayer), "create sentinel layer key");
        check(CoCreateGuid(&foreignFilter), "create sentinel filter key");
        FWPM_SUBLAYER0 layer{}; layer.subLayerKey = foreignLayer; layer.weight = 1;
        layer.displayData.name = const_cast<wchar_t*>(L"Rollback-only foreign sentinel");
        check(FwpmSubLayerAdd0(h, &layer, nullptr), "add foreign sentinel layer");
        FWPM_FILTER0 sentinel{}; sentinel.filterKey = foreignFilter; sentinel.subLayerKey = foreignLayer;
        sentinel.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4; sentinel.action.type = FWP_ACTION_BLOCK;
        sentinel.weight.type = FWP_UINT8; sentinel.weight.uint8 = 1;
        sentinel.displayData.name = const_cast<wchar_t*>(L"Rollback-only foreign sentinel");
        check(FwpmFilterAdd0(h, &sentinel, nullptr, nullptr), "add foreign sentinel");
        install(h, policy); expectMatch(h, policy, true); pass("production matcher accepts complete expected policy inside transaction");
        FWPM_FILTER0* remaining = nullptr;
        check(FwpmFilterGetByKey0(h, &foreignFilter, &remaining), "own erase preserves foreign sentinel");
        FwpmFreeMemory0(reinterpret_cast<void**>(&remaining));
        pass("own-policy replacement preserves foreign-sublayer sentinel");
        auto negative = [&](const char* name, const std::function<void()>& mutate) {
            mutate(); expectMatch(h, policy, false);
            install(h, policy); expectMatch(h, policy, true);
            pass(name);
        };
        negative("missing filter rejected; restored policy accepted", [&] { auto k = key(0); check(FwpmFilterDeleteByKey0(h, &k), "remove test filter"); });
        negative("extra filter rejected; restored policy accepted", [&] {
            auto f = filter(policy, 0); f.filterKey = key(4096); check(FwpmFilterAdd0(h, &f, nullptr, nullptr), "add extra test filter");
        });
        negative("same-count wrong action rejected", [&] { replace(h, policy, 0, [](auto& f, auto&, auto&) { f.action.type = FWP_ACTION_PERMIT; }); });
        negative("same-count wrong weight rejected", [&] { replace(h, policy, 0, [](auto&, auto&, auto& weight) { weight++; }); });
        negative("same-count wrong layer rejected", [&] { replace(h, policy, 0, [](auto& f, auto&, auto&) { f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6; }); });
        size_t app = withCondition(policy, FWPM_CONDITION_ALE_APP_ID);
        negative("same-count wrong application identity rejected", [&] {
            replace(h, policy, app, [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_ALE_APP_ID).conditionValue.byteBlob = policy.apps[0]; });
        });
        size_t endpoint = withCondition(policy, FWPM_CONDITION_IP_REMOTE_ADDRESS);
        negative("same-count wrong proxy address rejected", [&] { replace(h, policy, endpoint, [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_REMOTE_ADDRESS).conditionValue.uint32 ^= 1; }); });
        negative("same-count wrong proxy port rejected", [&] { replace(h, policy, endpoint, [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_REMOTE_PORT).conditionValue.uint16++; }); });
        negative("same-count wrong match type rejected", [&] { replace(h, policy, endpoint, [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_REMOTE_ADDRESS).matchType = FWP_MATCH_NOT_EQUAL; }); });
        negative("weakened endpoint condition set rejected", [&] { replace(h, policy, endpoint, [](auto&, auto& c, auto&) {
            c.erase(std::remove_if(c.begin(), c.end(), [](const auto& item) { return same(item.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT); }), c.end());
        }); });
        UINT64 wrongLuid = luid + 1;
        size_t tun = withCondition(policy, FWPM_CONDITION_IP_NEXTHOP_INTERFACE);
        negative("same-count wrong TUN LUID rejected", [&] { replace(h, policy, tun, [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_NEXTHOP_INTERFACE).conditionValue.uint64 = &wrongLuid; }); });
        for (size_t index : returnRules) {
            negative("TUN return wrong arrival LUID rejected", [&] {
                replace(h, policy, index, [&](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_ARRIVAL_INTERFACE).conditionValue.uint64 = &wrongLuid; });
            });
            negative("TUN return without reauthorization gate rejected", [&] {
                replace(h, policy, index, [](auto&, auto& c, auto&) {
                    c.erase(std::remove_if(c.begin(), c.end(), [](const auto& item) { return same(item.fieldKey, FWPM_CONDITION_FLAGS); }), c.end());
                });
            });
            negative("Blanket reauthorization permit without TUN arrival rejected", [&] {
                replace(h, policy, index, [](auto&, auto& c, auto&) {
                    c.erase(std::remove_if(c.begin(), c.end(), [](const auto& item) { return same(item.fieldKey, FWPM_CONDITION_IP_ARRIVAL_INTERFACE); }), c.end());
                });
            });
            negative("TUN return changed flag match semantics rejected", [&] {
                replace(h, policy, index, [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_FLAGS).matchType = FWP_MATCH_FLAGS_ANY_SET; });
            });
            negative("TUN return substituted local interface rejected", [&] {
                replace(h, policy, index, [](auto&, auto& c, auto&) { condition(c, FWPM_CONDITION_IP_ARRIVAL_INTERFACE).fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE; });
            });
        }
        negative("authorization flags change rejected", [&] { replace(h, policy, 1, [](auto& f, auto&, auto&) { f.flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT; }); });
        negative("changed sublayer weight rejected", [&] { install(h, policy, 0xfffe); });
        // Invalid inputs exercise the real builder only, without any export that
        // could commit. Each failed builder owns and releases its allocated data.
        auto invalid = [&](UINT32 address, UINT16 proxyPort, const wchar_t* exe, const wchar_t* const* apps, UINT32 count) {
            Policy bad{};
            require(build(bad, address, proxyPort, luid, exe, apps, count) == ERROR_INVALID_PARAMETER, "invalid native input was not rejected");
            expectMatch(h, policy, true);
        };
        invalid(0, port, engine, excluded, 1); invalid(0x7f000001, port, engine, excluded, 1);
        invalid(ip, 0, engine, excluded, 1); invalid(ip, port, nullptr, excluded, 1);
        invalid(ip, port, L"relative.exe", excluded, 1); invalid(ip, port, engine, nullptr, 1);
        invalid(ip, port, engine, excluded, 65);
        const wchar_t* self[] = { engine }; invalid(ip, port, engine, self, 1);
        const wchar_t* relative[] = { L"relative.exe" }; invalid(ip, port, engine, relative, 1);
        pass("invalid native inputs rejected without changing transaction policy");
        dnsTests(h, ip, port, luid, engine, excluded);
    } catch (...) { failure = std::current_exception(); }
    transaction.abort();
    require(snapshot(h) == before, "committed own-policy snapshot changed after rollback");
    pass("full committed own-policy snapshot unchanged after explicit rollback");
    FWPM_FILTER0* residue = nullptr;
    DWORD residueError = FwpmFilterGetByKey0(h, &foreignFilter, &residue);
    if (residue) FwpmFreeMemory0(reinterpret_cast<void**>(&residue));
    require(residueError == FWP_E_FILTER_NOT_FOUND, "foreign sentinel survived rollback or query failed");
    pass("uncommitted foreign sentinel absent after rollback");
    if (failure) std::rethrow_exception(failure);
}
} // namespace audit

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3) throw std::runtime_error("usage: guard-policy-tests.exe <engine.exe> <alternate.exe>");
        audit::AppLock appLock;
        audit::EngineHandle engine;
        audit::run(engine.handle, argv[1], argv[2]);
        std::cout << "SKIP: dynamic session lifetime/owner rundown, live traffic, existing connections, crashes, DNS/IPv6/UDP and TUN readiness are not exercised" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cout << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
