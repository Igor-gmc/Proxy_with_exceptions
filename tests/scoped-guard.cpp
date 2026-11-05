// Diagnostic-only DLL. Reuses the production rule builder, never its mutators.
// The harness calls only ScopedStart/ScopedStop. The included Guard* exports
// are not part of this diagnostic's API and MUST NOT be called by the harness.
#include "../native/guard.cpp"

namespace scoped_audit {
static SRWLOCK lock=SRWLOCK_INIT;
static HANDLE ownedSession=nullptr;
static GUID ownedSublayer{};
static const GUID emptyGuid{};
struct Lock {
    Lock() { AcquireSRWLockExclusive(&lock); }
    ~Lock() { ReleaseSRWLockExclusive(&lock); }
};

static DWORD uuid(GUID& result) {
    RPC_STATUS status=UuidCreate(&result);
    return status==RPC_S_OK || status==RPC_S_UUID_LOCAL_ONLY ? ERROR_SUCCESS : status;
}

static DWORD closeOwned() {
    if(ownedSession) {
        DWORD error=FwpmEngineClose0(ownedSession);
        // Retain the only owner handle on failure so ScopedStop can retry.
        if(error) return error;
        ownedSession=nullptr;
    }
    if(same(ownedSublayer,emptyGuid)) return ERROR_SUCCESS;
    // Do not equate closing a handle with verified disappearance. Retain the
    // random identity until an independent read confirms its sublayer is gone.
    WfpSession read;
    DWORD error=open(&read.handle); if(error) return error;
    FWPM_SUBLAYER0* actual=nullptr;
    error=FwpmSubLayerGetByKey0(read.handle,&ownedSublayer,&actual);
    if(actual) FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    if(error==FWP_E_SUBLAYER_NOT_FOUND) { ownedSublayer=GUID{}; return ERROR_SUCCESS; }
    return error ? error : ERROR_BUSY;
}

static DWORD countOwned(UINT32* count) {
    if(!count) return ERROR_INVALID_PARAMETER;
    *count=0;
    if(same(ownedSublayer,emptyGuid)) return ERROR_SUCCESS;
    WfpSession read;
    HANDLE handle=ownedSession;
    DWORD error=0;
    if(!handle) { error=open(&read.handle); if(error) return error; handle=read.handle; }
    HANDLE enumeration=nullptr;
    error=FwpmFilterCreateEnumHandle0(handle,nullptr,&enumeration); if(error) return error;
    while(!error) {
        FWPM_FILTER0** filters=nullptr; UINT32 found=0;
        error=FwpmFilterEnum0(handle,enumeration,128,&filters,&found);
        if(!error) for(UINT32 i=0;i<found;i++) if(same(filters[i]->subLayerKey,ownedSublayer)) ++*count;
        if(filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        if(error || found<128) break;
    }
    DWORD cleanup=FwpmFilterDestroyEnumHandle0(handle,enumeration);
    return error ? error : cleanup;
}

static bool appEquals(const FWPM_FILTER_CONDITION0& condition,FWP_BYTE_BLOB* app) {
    auto expected=appCondition(app);
    return same(condition.fieldKey,expected.fieldKey) && condition.matchType==FWP_MATCH_EQUAL &&
        valueEqual(condition.conditionValue,expected.conditionValue);
}

static size_t bitCount(UINT32 mask) {
    size_t count=0;
    while(mask) { count+=mask & 1U; mask>>=1; }
    return count;
}

static bool isTunReturnRule(const Rule& rule,UINT64 luid) {
    if(!rule.active || rule.action!=FWP_ACTION_PERMIT || rule.weight!=100 || rule.conditions.size()!=2 ||
        (!same(rule.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V4) && !same(rule.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V6))) return false;
    bool arrival=false,reauth=false;
    for(const auto& condition:rule.conditions) {
        if(same(condition.fieldKey,FWPM_CONDITION_IP_ARRIVAL_INTERFACE) && condition.matchType==FWP_MATCH_EQUAL &&
            condition.conditionValue.type==FWP_UINT64 && condition.conditionValue.uint64 && *condition.conditionValue.uint64==luid)
            arrival=true;
        if(same(condition.fieldKey,FWPM_CONDITION_FLAGS) && condition.matchType==FWP_MATCH_FLAGS_ALL_SET &&
            condition.conditionValue.type==FWP_UINT32 && condition.conditionValue.uint32==FWP_CONDITION_FLAG_IS_REAUTHORIZE)
            reauth=true;
    }
    return arrival && reauth;
}

static DWORD selectTunReturnPolicy(Policy& policy,bool allowTunReturn) {
    size_t v4=0,v6=0;
    for(const auto& rule:policy.rules) if(isTunReturnRule(rule,policy.luid)) {
        if(same(rule.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V4)) ++v4;
        else ++v6;
    }
    if(v4!=1 || v6!=1) return ERROR_INVALID_DATA;
    // true exercises the real production builder. false deliberately removes
    // only the exact two new rules to preserve the historical failing control.
    if(!allowTunReturn) policy.rules.erase(std::remove_if(policy.rules.begin(),policy.rules.end(),
        [&](const Rule& rule){ return isTunReturnRule(rule,policy.luid); }),policy.rules.end());
    return ERROR_SUCCESS;
}

static DWORD transform(Policy& policy,UINT32 blockAppMask,UINT32 blockLayerMask,bool allowTunReturn) {
    if(policy.apps.size()!=2 || !policy.luid || !blockAppMask || (blockAppMask & ~3U) ||
        !blockLayerMask || (blockLayerMask & ~15U)) return ERROR_INVALID_DATA;
    std::vector<Rule> scoped;
    size_t removed=0,blocks=0,genericPermits=0,enginePermits=0;
    for(const auto& original:policy.rules) {
        if(original.action==FWP_ACTION_PERMIT && original.conditions.size()==1 &&
            appEquals(original.conditions[0],policy.apps[1])) {
            ++removed; // Synthetic placeholder exclusion is never installed.
            continue;
        }
        bool hasApp=false;
        for(const auto& condition:original.conditions) if(same(condition.fieldKey,FWPM_CONDITION_ALE_APP_ID)) {
            if(hasApp || !appEquals(condition,policy.apps[0])) return ERROR_INVALID_DATA;
            hasApp=true;
        }
        if(original.action==FWP_ACTION_BLOCK) {
            if(!original.conditions.empty() || original.weight!=10) return ERROR_INVALID_DATA;
            ++blocks;
            const GUID layers[]={FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
            UINT32 layerBit=0;
            for(unsigned i=0;i<4;i++) if(same(original.layer,layers[i])) layerBit=1U<<i;
            if(!layerBit) return ERROR_INVALID_DATA;
            if(!(blockLayerMask & layerBit)) continue;
        } else if(original.action==FWP_ACTION_PERMIT) {
            if(original.weight!=100) return ERROR_INVALID_DATA;
            if(hasApp) ++enginePermits;
            else ++genericPermits;
        } else return ERROR_INVALID_DATA;

        if(hasApp) scoped.push_back(original);
        else for(size_t appIndex=0;appIndex<policy.apps.size();appIndex++) {
            if(original.action==FWP_ACTION_BLOCK && !(blockAppMask & (1U<<appIndex))) continue;
            Rule rule=original;
            rule.conditions.push_back(appCondition(policy.apps[appIndex]));
            scoped.push_back(std::move(rule));
        }
    }
    // This invariant intentionally fails when the production builder changes.
    // Four BLOCKs, eight generic permits, five engine permits, four exclusions.
    size_t expectedGeneric=allowTunReturn ? 10 : 8;
    size_t expectedCount=(allowTunReturn ? 25 : 21)+bitCount(blockAppMask)*bitCount(blockLayerMask);
    if(removed!=4 || blocks!=4 || genericPermits!=expectedGeneric || enginePermits!=5 || scoped.size()!=expectedCount)
        return ERROR_INVALID_DATA;
    for(auto& rule:scoped) {
        size_t appCount=0;
        for(const auto& condition:rule.conditions) if(same(condition.fieldKey,FWPM_CONDITION_ALE_APP_ID)) {
            if(!appEquals(condition,policy.apps[0]) && !appEquals(condition,policy.apps[1])) return ERROR_INVALID_DATA;
            ++appCount;
        }
        if(appCount!=1) return ERROR_INVALID_DATA;
        rule.active=true; // Every test filter is nonpersistent.
    }
    policy.rules=std::move(scoped);
    return ERROR_SUCCESS;
}

static DWORD install(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* parent,UINT32 blockAppMask,UINT32 blockLayerMask,bool allowTunReturn) {
    if(ownedSession || !same(ownedSublayer,emptyGuid)) return ERROR_BUSY;
    if(!luid || !absolutePath(parent) || !absolutePath(engine) || !_wcsicmp(engine,parent) ||
        !blockAppMask || (blockAppMask & ~3U) || !blockLayerMask || (blockLayerMask & ~15U))
        return ERROR_INVALID_PARAMETER;
    // Read-only gate. Never remove or reconfigure an existing production guard.
    UINT32 productionCount=0;
    DWORD error=GuardStatus(&productionCount);
    if(error) return error;
    if(productionCount) return ERROR_BUSY;

    const wchar_t* excluded[]={parent};
    Policy policy{};
    error=build(policy,ip,port,luid,engine,excluded,1,false); if(error) return error;
    error=selectTunReturnPolicy(policy,allowTunReturn); if(error) return error;
    error=transform(policy,blockAppMask,blockLayerMask,allowTunReturn); if(error) return error;
    GUID sessionKey{},sublayerKey{};
    error=uuid(sessionKey); if(error) return error;
    error=uuid(sublayerKey); if(error) return error;
    if(same(sublayerKey,sublayer)) return ERROR_INVALID_DATA;
    std::vector<GUID> keys(policy.rules.size());
    for(auto& key:keys) { error=uuid(key); if(error) return error; }
    for(const auto& randomKey:keys) for(unsigned slot=0;slot<2048;slot++)
        if(same(randomKey,key(slot))) return ERROR_INVALID_DATA;
    for(size_t i=0;i<keys.size();i++) for(size_t j=0;j<i;j++)
        if(same(keys[i],keys[j])) return ERROR_INVALID_DATA;

    FWPM_SESSION0 options{};
    options.flags=FWPM_SESSION_FLAG_DYNAMIC;
    options.sessionKey=sessionKey;
    options.displayData.name=const_cast<wchar_t*>(L"ProxyBridge scoped diagnostic");
    error=FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&options,&ownedSession);
    if(error) { ownedSession=nullptr; return error; }
    ownedSublayer=sublayerKey;
    Transaction transaction(ownedSession);
    error=transaction.begin(); if(error) return error;
    FWPM_SUBLAYER0 layer{};
    layer.subLayerKey=sublayerKey; layer.weight=0xffff;
    layer.displayData.name=const_cast<wchar_t*>(L"ProxyBridge scoped diagnostic");
    // flags=0 plus the owning dynamic session makes the sublayer ephemeral.
    error=FwpmSubLayerAdd0(ownedSession,&layer,nullptr); if(error) return error;
    for(size_t i=0;i<policy.rules.size();i++) {
        auto expected=filter(policy,i);
        expected.filterKey=keys[i]; expected.subLayerKey=sublayerKey; expected.flags=0;
        expected.displayData.name=const_cast<wchar_t*>(L"ProxyBridge scoped diagnostic");
        error=FwpmFilterAdd0(ownedSession,&expected,nullptr,nullptr); if(error) return error;
        FWPM_FILTER0* actual=nullptr;
        error=FwpmFilterGetByKey0(ownedSession,&keys[i],&actual); if(error) return error;
        bool exact=filterEqual(*actual,expected);
        FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
        if(!exact) return ERROR_INVALID_DATA;
    }
    // A second read-only gate catches production protection appearing while
    // this transaction was prepared. Never intentionally coexist with it.
    std::vector<UINT64> productionIds;
    // Read through this transaction's handle, avoiding a cross-session query
    // while a write transaction is open. ownFilters only enumerates here.
    error=ownFilters(ownedSession,productionIds); if(error) return error;
    if(!productionIds.empty()) return ERROR_BUSY;
    return transaction.commit();
}
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStartWithReauth(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* parent,UINT32 blockAppMask,UINT32 blockLayerMask,BOOL allowTunReturn) {
    scoped_audit::Lock lock;
    // An existing (including cleanup-failed) session belongs to an earlier
    // invocation; a rejected new start must not close it.
    if(scoped_audit::ownedSession || !same(scoped_audit::ownedSublayer,scoped_audit::emptyGuid)) return ERROR_BUSY;
    DWORD error=ERROR_GEN_FAILURE;
    try { error=scoped_audit::install(ip,port,luid,engine,parent,blockAppMask,blockLayerMask,allowTunReturn!=FALSE); }
    catch(const std::bad_alloc&) { error=ERROR_NOT_ENOUGH_MEMORY; }
    catch(...) { error=ERROR_GEN_FAILURE; }
    if(error) {
        DWORD cleanup=scoped_audit::closeOwned();
        if(cleanup) detail(L"scoped/cleanup-close-failed",cleanup,error);
    }
    return error;
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStartWithLayers(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* parent,UINT32 blockAppMask,UINT32 blockLayerMask) {
    return ScopedStartWithReauth(ip,port,luid,engine,parent,blockAppMask,blockLayerMask,FALSE);
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStartWithMask(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* parent,UINT32 blockAppMask) {
    return ScopedStartWithLayers(ip,port,luid,engine,parent,blockAppMask,15);
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStart(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* parent) {
    return ScopedStartWithMask(ip,port,luid,engine,parent,3);
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStop() {
    scoped_audit::Lock lock;
    return scoped_audit::closeOwned();
}

extern "C" __declspec(dllexport) DWORD __cdecl ScopedStatus(UINT32* count) {
    scoped_audit::Lock lock;
    return scoped_audit::countOwned(count);
}
