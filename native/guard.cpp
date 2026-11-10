#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <aclapi.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <new>
#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

// This sublayer is exclusively owned by ProxyBridge, including the legacy policy.
static const GUID sublayer = {0x57b2d8e0,0x19ad,0x46e2,{0x97,0x14,0x36,0x11,0x99,0xb2,0xe1,0x01}};
static GUID key(unsigned n) { GUID k = sublayer; k.Data1 += 101 + n; return k; }
static bool same(const GUID& a, const GUID& b) { return !!IsEqualGUID(a,b); }
// Per-thread diagnostic contains only operation names and numeric metadata.
// It never includes executable paths, proxy endpoints or credentials.
static thread_local wchar_t diagnostic[256]=L"";
static void detail(const wchar_t* field,UINT64 actual=0,UINT64 expected=0,UINT64 index=0) {
    _snwprintf_s(diagnostic,_countof(diagnostic),_TRUNCATE,L"%s; actual=%llu; expected=%llu; index=%llu",field,actual,expected,index);
}
extern "C" __declspec(dllexport) const wchar_t* __cdecl GuardLastDiagnostic() { return diagnostic; }
extern "C" __declspec(dllexport) HANDLE __cdecl CreateEngineJob() {
    HANDLE job=CreateJobObjectW(nullptr,nullptr); if(!job) return nullptr;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
    info.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&info,sizeof(info))) { CloseHandle(job); return nullptr; }
    return job;
}
static DWORD open(HANDLE* h) { return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, h); }
struct Rule {
    GUID layer;
    FWP_ACTION_TYPE action;
    UINT64 weight;
    std::vector<FWPM_FILTER_CONDITION0> conditions;
    bool active=false;
    unsigned slot=0;
};
// V5 ABI: no pointers or platform-sized fields in an address entry. IPv4 uses
// the first four network-order bytes; the remaining bytes must be zero.
struct AddressExclusion {
    UINT32 family;
    UINT32 prefixLength;
    UINT32 port; // Zero means any TCP/UDP destination port except DNS (53).
    BYTE address[16];
};
static_assert(sizeof(AddressExclusion)==28,"AddressExclusion ABI size changed");
struct Policy {
    UINT64 luid;
    std::vector<FWP_BYTE_BLOB*> apps;
    std::vector<Rule> rules;
    struct AddressRange {
        UINT32 family;
        UINT16 port;
        FWP_V4_ADDR_AND_MASK v4{};
        FWP_V6_ADDR_AND_MASK v6{};
    };
    std::vector<AddressRange> addressRanges;
    struct DnsEndpoint { UINT64 luid; UINT32 ipv4; FWP_BYTE_ARRAY16 ipv6; bool v6; };
    std::vector<DnsEndpoint> dns;
    FWP_BYTE_BLOB dnsIdentity{};
    ~Policy() {
        for(auto app:apps) FwpmFreeMemory0(reinterpret_cast<void**>(&app));
        if(dnsIdentity.data) LocalFree(dnsIdentity.data);
    }
};
static FWPM_FILTER_CONDITION0 number(const GUID& field, FWP_DATA_TYPE type, UINT32 value, FWP_MATCH_TYPE match=FWP_MATCH_EQUAL) {
    FWPM_FILTER_CONDITION0 c{}; c.fieldKey=field; c.matchType=match; c.conditionValue.type=type;
    if(type==FWP_UINT8) c.conditionValue.uint8=static_cast<UINT8>(value);
    else if(type==FWP_UINT16) c.conditionValue.uint16=static_cast<UINT16>(value);
    else c.conditionValue.uint32=value;
    return c;
}
static FWPM_FILTER_CONDITION0 appCondition(FWP_BYTE_BLOB* app) {
    FWPM_FILTER_CONDITION0 c{}; c.fieldKey=FWPM_CONDITION_ALE_APP_ID; c.matchType=FWP_MATCH_EQUAL;
    c.conditionValue.type=FWP_BYTE_BLOB_TYPE; c.conditionValue.byteBlob=app; return c;
}
static bool absolutePath(const wchar_t* path) {
    if(!path || !*path) return false;
    size_t n=wcslen(path);
    return n>3 && ((path[1]==L':' && (path[2]==L'\\' || path[2]==L'/')) || (path[0]==L'\\' && path[1]==L'\\'));
}
static DWORD addressRanges(Policy& p,const AddressExclusion* addresses,UINT32 count) {
    if(count>64 || (count && !addresses)) return ERROR_INVALID_PARAMETER;
    // Finish allocating every mask before rules retain pointers to this vector.
    p.addressRanges.reserve(count);
    for(UINT32 i=0;i<count;i++) {
        const auto& a=addresses[i];
        if((a.family!=4 && a.family!=6) || a.prefixLength>(a.family==4 ? 32u : 128u) ||
            a.port>65535 || a.port==53) return ERROR_INVALID_PARAMETER;
        UINT32 bytes=a.family==4 ? 4 : 16;
        for(UINT32 j=0;j<16;j++) {
            UINT32 remaining=a.prefixLength>j*8 ? a.prefixLength-j*8 : 0;
            UINT32 prefix=remaining>8 ? 8 : remaining;
            BYTE mask=static_cast<BYTE>(0xffu << (8-prefix));
            if((j>=bytes && a.address[j]) || (a.address[j] & static_cast<BYTE>(~mask))) return ERROR_INVALID_PARAMETER;
        }
        const BYTE mappedPrefix[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        if(a.family==6 && !memcmp(a.address,mappedPrefix,12)) return ERROR_INVALID_PARAMETER;
        Policy::AddressRange range{}; range.family=a.family; range.port=static_cast<UINT16>(a.port);
        if(a.family==4) {
            range.v4.addr=(static_cast<UINT32>(a.address[0])<<24) | (static_cast<UINT32>(a.address[1])<<16) |
                (static_cast<UINT32>(a.address[2])<<8) | a.address[3];
            range.v4.mask=a.prefixLength ? (0xffffffffu << (32-a.prefixLength)) : 0;
        } else {
            memcpy(range.v6.addr,a.address,16); range.v6.prefixLength=static_cast<UINT8>(a.prefixLength);
        }
        p.addressRanges.push_back(range);
    }
    return ERROR_SUCCESS;
}
static DWORD stoppedDns(Policy& p) {
    // Match the Dnscache service SID, never every svchost or every port 53
    // connection. SERVICE_SID_TYPE_NONE cannot satisfy this contract.
    SC_HANDLE manager=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(!manager) return GetLastError();
    SC_HANDLE service=OpenServiceW(manager,L"Dnscache",SERVICE_QUERY_CONFIG);
    DWORD e=service ? ERROR_SUCCESS : GetLastError();
    SERVICE_SID_INFO sid{}; DWORD needed=0;
    if(!e && !QueryServiceConfig2W(service,SERVICE_CONFIG_SERVICE_SID_INFO,reinterpret_cast<BYTE*>(&sid),sizeof(sid),&needed)) e=GetLastError();
    if(service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if(e) return e;
    if(!(sid.dwServiceSidType & SERVICE_SID_TYPE_UNRESTRICTED)) return ERROR_NOT_SUPPORTED;
    EXPLICIT_ACCESS_W access{};
    BuildExplicitAccessWithNameW(&access,const_cast<wchar_t*>(L"NT SERVICE\\Dnscache"),FWP_ACTRL_MATCH_FILTER,GRANT_ACCESS,0);
    PSECURITY_DESCRIPTOR descriptor=nullptr; ULONG length=0;
    e=BuildSecurityDescriptorW(nullptr,nullptr,1,&access,0,nullptr,nullptr,&length,&descriptor);
    if(e) return e;
    p.dnsIdentity={length,reinterpret_cast<UINT8*>(descriptor)};
    wchar_t system[MAX_PATH]; UINT chars=GetSystemDirectoryW(system,_countof(system));
    if(!chars) return GetLastError();
    if(chars>=_countof(system)-13) return ERROR_INSUFFICIENT_BUFFER;
    wcscat_s(system,L"\\svchost.exe");
    FWP_BYTE_BLOB* app=nullptr;
    e=FwpmGetAppIdFromFileName0(system,&app); if(e) return e;
    p.apps.push_back(app);

    ULONG bytes=16384; std::vector<BYTE> storage;
    for(int attempt=0;attempt<3;attempt++) {
        storage.resize(bytes);
        e=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_UNICAST|GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST,
            nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),&bytes);
        if(e!=ERROR_BUFFER_OVERFLOW) break;
        if(bytes>4*1024*1024) return ERROR_INSUFFICIENT_BUFFER;
    }
    if(e==ERROR_NO_DATA) return ERROR_SUCCESS;
    if(e) return e;
    for(auto a=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());a;a=a->Next) {
        if(a->OperStatus!=IfOperStatusUp || a->IfType==IF_TYPE_SOFTWARE_LOOPBACK || !a->Luid.Value ||
            (a->FriendlyName && _wcsicmp(a->FriendlyName,L"ProxyBridge-TUN")==0) ||
            (a->Description && _wcsicmp(a->Description,L"sing-tun Tunnel")==0)) continue;
        for(auto d=a->FirstDnsServerAddress;d;d=d->Next) {
            if(!d->Address.lpSockaddr) continue;
            Policy::DnsEndpoint endpoint{}; endpoint.luid=a->Luid.Value;
            if(d->Address.lpSockaddr->sa_family==AF_INET && d->Address.iSockaddrLength>=static_cast<int>(sizeof(SOCKADDR_IN))) {
                auto address=reinterpret_cast<SOCKADDR_IN*>(d->Address.lpSockaddr);
                endpoint.ipv4=ntohl(address->sin_addr.s_addr);
                if(!endpoint.ipv4 || (endpoint.ipv4>>24)==127 || (endpoint.ipv4>>28)>=14 ||
                    (endpoint.ipv4 & 0xfffffffc)==0xac1de700) continue;
            } else if(d->Address.lpSockaddr->sa_family==AF_INET6 && d->Address.iSockaddrLength>=static_cast<int>(sizeof(SOCKADDR_IN6))) {
                auto address=reinterpret_cast<SOCKADDR_IN6*>(d->Address.lpSockaddr);
                endpoint.v6=true; memcpy(endpoint.ipv6.byteArray16,&address->sin6_addr,16);
                const BYTE zero[16]={},loopback[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
                const BYTE tunPrefix[12]={0xfd,0xfe,0xdc,0xba,0x72,0x31,0,0,0,0,0,0};
                if(!memcmp(endpoint.ipv6.byteArray16,zero,16) || !memcmp(endpoint.ipv6.byteArray16,loopback,16) ||
                    endpoint.ipv6.byteArray16[0]==0xff || !memcmp(endpoint.ipv6.byteArray16,tunPrefix,12)) continue;
            } else continue;
            p.dns.push_back(endpoint);
            if(p.dns.size()>256) return ERROR_INSUFFICIENT_BUFFER;
        }
    }
    auto less=[](const Policy::DnsEndpoint& a,const Policy::DnsEndpoint& b) {
        if(a.v6!=b.v6) return a.v6<b.v6;
        if(a.luid!=b.luid) return a.luid<b.luid;
        return a.v6 ? memcmp(a.ipv6.byteArray16,b.ipv6.byteArray16,16)<0 : a.ipv4<b.ipv4;
    };
    std::sort(p.dns.begin(),p.dns.end(),less);
    p.dns.erase(std::unique(p.dns.begin(),p.dns.end(),[&](const auto& a,const auto& b){ return !less(a,b) && !less(b,a); }),p.dns.end());
    if(p.dns.size()>64) return ERROR_INSUFFICIENT_BUFFER;
    unsigned slot=512;
    for(auto& endpoint:p.dns) for(auto protocol:{IPPROTO_TCP,IPPROTO_UDP}) {
        FWPM_FILTER_CONDITION0 identity{};
        identity.fieldKey=FWPM_CONDITION_ALE_USER_ID; identity.matchType=FWP_MATCH_EQUAL;
        identity.conditionValue.type=FWP_SECURITY_DESCRIPTOR_TYPE; identity.conditionValue.sd=&p.dnsIdentity;
        auto remote=number(FWPM_CONDITION_IP_REMOTE_ADDRESS,FWP_UINT32,endpoint.ipv4);
        if(endpoint.v6) { remote.conditionValue.type=FWP_BYTE_ARRAY16_TYPE; remote.conditionValue.byteArray16=&endpoint.ipv6; }
        FWPM_FILTER_CONDITION0 nic{}; nic.fieldKey=FWPM_CONDITION_IP_NEXTHOP_INTERFACE; nic.matchType=FWP_MATCH_EQUAL;
        nic.conditionValue.type=FWP_UINT64; nic.conditionValue.uint64=&endpoint.luid;
        p.rules.push_back({endpoint.v6 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWP_ACTION_PERMIT,100,
            {appCondition(app),identity,remote,number(FWPM_CONDITION_IP_REMOTE_PORT,FWP_UINT16,53),
            number(FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,protocol),nic},false,slot++});
    }
    return ERROR_SUCCESS;
}
static DWORD build(Policy& p,UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,bool allowStoppedDns=false,const AddressExclusion* addresses=nullptr,UINT32 addressCount=0) {
    if(!ip || (ip>>24)==127 || !port || !absolutePath(engine) || count>64 || (count && !excluded)) return ERROR_INVALID_PARAMETER;
    if(allowStoppedDns && luid) return ERROR_INVALID_PARAMETER;
    DWORD addressError=addressRanges(p,addresses,addressCount); if(addressError) return addressError;
    p.luid=luid;
    for(UINT32 i=0;i<=count;i++) {
        const wchar_t* path=i ? excluded[i-1] : engine;
        if(!absolutePath(path)) return ERROR_INVALID_PARAMETER;
        if(i && _wcsicmp(path,engine)==0) return ERROR_INVALID_PARAMETER;
        FWP_BYTE_BLOB* app{};
        DWORD e=FwpmGetAppIdFromFileName0(path,&app); if(e) return e;
        p.apps.push_back(app);
    }
    const GUID layers[]={FWPM_LAYER_ALE_AUTH_CONNECT_V4,FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
    for(int i=0;i<4;i++) {
        const GUID& layer=layers[i];
        // Highest matching rule wins within our sublayer. Permits remain soft,
        // so another provider (including antivirus) can still deny a connection.
        p.rules.push_back({layer,FWP_ACTION_BLOCK,10,{}});
        p.rules.push_back({layer,FWP_ACTION_PERMIT,100,{number(FWPM_CONDITION_FLAGS,FWP_UINT32,FWP_CONDITION_FLAG_IS_LOOPBACK,FWP_MATCH_FLAGS_ALL_SET)}});
        for(UINT32 j=1;j<=count;j++) p.rules.push_back({layer,FWP_ACTION_PERMIT,100,{appCondition(p.apps[j])}});
        if(i==0) p.rules.push_back({layer,FWP_ACTION_PERMIT,100,{
            appCondition(p.apps[0]), number(FWPM_CONDITION_IP_REMOTE_ADDRESS,FWP_UINT32,ip),
            number(FWPM_CONDITION_IP_REMOTE_PORT,FWP_UINT16,port),number(FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,IPPROTO_TCP)}});
    }
    for(size_t i=0;i<p.rules.size();i++) p.rules[i].slot=static_cast<unsigned>(i);
    // LAN routes can be more specific than the TUN routes. These destination
    // permits cover both direct LAN traffic and the engine's direct outbound.
    // They never authorize unsolicited inbound traffic or direct port-53 DNS.
    unsigned addressSlot=2048;
    for(auto& range:p.addressRanges) for(auto protocol:{IPPROTO_TCP,IPPROTO_UDP}) {
        FWPM_FILTER_CONDITION0 remote{};
        remote.fieldKey=FWPM_CONDITION_IP_REMOTE_ADDRESS; remote.matchType=FWP_MATCH_EQUAL;
        if(range.family==4) { remote.conditionValue.type=FWP_V4_ADDR_MASK; remote.conditionValue.v4AddrMask=&range.v4; }
        else { remote.conditionValue.type=FWP_V6_ADDR_MASK; remote.conditionValue.v6AddrMask=&range.v6; }
        auto remotePort=number(FWPM_CONDITION_IP_REMOTE_PORT,FWP_UINT16,range.port ? range.port : 53,
            range.port ? FWP_MATCH_EQUAL : FWP_MATCH_NOT_EQUAL);
        p.rules.push_back({range.family==4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWP_ACTION_PERMIT,100,{remote,remotePort,number(FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,protocol)},false,addressSlot++});
    }
    if(allowStoppedDns && count) { DWORD e=stoppedDns(p); if(e) return e; }
    // Baseline is persistent. Active permissions have a separate key range
    // and MUST be installed through the process-owned dynamic session.
    unsigned activeSlot=1024;
    if(luid) for(int i=0;i<4;i++) {
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey=i<2 ? FWPM_CONDITION_IP_NEXTHOP_INTERFACE : FWPM_CONDITION_IP_LOCAL_INTERFACE;
        c.matchType=FWP_MATCH_EQUAL; c.conditionValue.type=FWP_UINT64; c.conditionValue.uint64=&p.luid;
        p.rules.push_back({layers[i],FWP_ACTION_PERMIT,100,{c},true,activeSlot++});
        // Binary and runtime config remain restricted to elevated users.
        if(i<2 && count) for(auto protocol:{IPPROTO_TCP,IPPROTO_UDP})
            p.rules.push_back({layers[i],FWP_ACTION_PERMIT,100,{appCondition(p.apps[0]),number(FWPM_CONDITION_IP_PROTOCOL,FWP_UINT8,protocol)},true,activeSlot++});
    }
    // An outbound ALE flow can be reauthorized on an inbound response. In
    // that classification NEXTHOP_INTERFACE is empty: match the actual arrival
    // interface instead, only for reauthorization and only while this TUN's
    // dynamic session exists. Initial outbound authorization remains strict.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/network/filtering-condition-identifiers
    if(luid) for(int i=0;i<2;i++) {
        FWPM_FILTER_CONDITION0 arrival{};
        arrival.fieldKey=FWPM_CONDITION_IP_ARRIVAL_INTERFACE;
        arrival.matchType=FWP_MATCH_EQUAL;
        arrival.conditionValue.type=FWP_UINT64;
        arrival.conditionValue.uint64=&p.luid;
        p.rules.push_back({layers[i],FWP_ACTION_PERMIT,100,{arrival,
            number(FWPM_CONDITION_FLAGS,FWP_UINT32,FWP_CONDITION_FLAG_IS_REAUTHORIZE,FWP_MATCH_FLAGS_ALL_SET)},true,activeSlot++});
    }
    return ERROR_SUCCESS;
}
static FWPM_FILTER0 filter(Policy& p,size_t i) {
    auto& r=p.rules[i]; FWPM_FILTER0 f{}; f.filterKey=key(r.slot);
    f.displayData.name=const_cast<wchar_t*>(L"ProxyBridge KillSwitch v3");
    f.flags=r.active ? 0 : FWPM_FILTER_FLAG_PERSISTENT; f.layerKey=r.layer; f.subLayerKey=sublayer;
    f.action.type=r.action; f.weight.type=FWP_UINT64; f.weight.uint64=&r.weight;
    f.numFilterConditions=static_cast<UINT32>(r.conditions.size()); f.filterCondition=r.conditions.data(); return f;
}
// Enumerate all filters, selecting solely our own sublayer. This also migrates
// all nine old packet/transport rules and handles variable exception counts.
static DWORD ownFilters(HANDLE h,std::vector<UINT64>& ids) {
    HANDLE enumeration{}; DWORD e=FwpmFilterCreateEnumHandle0(h,nullptr,&enumeration); if(e) return e;
    while(!e) {
        FWPM_FILTER0** filters{}; UINT32 count{};
        e=FwpmFilterEnum0(h,enumeration,128,&filters,&count);
        if(!e) for(UINT32 i=0;i<count;i++) if(same(filters[i]->subLayerKey,sublayer)) ids.push_back(filters[i]->filterId);
        if(filters) FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        if(e || count<128) break;
    }
    FwpmFilterDestroyEnumHandle0(h,enumeration); return e;
}
static DWORD erase(HANDLE h) {
    // Generic helper retained for Abort-only shape tests. Production callers
    // must use erasePersistent after their own dynamic session has been closed.
    std::vector<UINT64> ids; DWORD e=ownFilters(h,ids); if(e) return e;
    for(auto id:ids) { e=FwpmFilterDeleteById0(h,id); if(e) return e; } return ERROR_SUCCESS;
}
static bool valueEqual(const FWP_CONDITION_VALUE0& a,const FWP_CONDITION_VALUE0& b) {
    if(a.type!=b.type) return false;
    switch(a.type) {
    case FWP_UINT8: return a.uint8==b.uint8;
    case FWP_UINT16: return a.uint16==b.uint16;
    case FWP_UINT32: return a.uint32==b.uint32;
    case FWP_UINT64: return a.uint64 && b.uint64 && *a.uint64==*b.uint64;
    case FWP_BYTE_BLOB_TYPE: return a.byteBlob && b.byteBlob && a.byteBlob->size==b.byteBlob->size &&
        (!a.byteBlob->size || !memcmp(a.byteBlob->data,b.byteBlob->data,a.byteBlob->size));
    case FWP_SECURITY_DESCRIPTOR_TYPE: return a.sd && b.sd && a.sd->size==b.sd->size &&
        (!a.sd->size || (a.sd->data && b.sd->data && !memcmp(a.sd->data,b.sd->data,a.sd->size)));
    case FWP_BYTE_ARRAY16_TYPE: return a.byteArray16 && b.byteArray16 && !memcmp(a.byteArray16,b.byteArray16,16);
    case FWP_V4_ADDR_MASK: return a.v4AddrMask && b.v4AddrMask && a.v4AddrMask->addr==b.v4AddrMask->addr &&
        a.v4AddrMask->mask==b.v4AddrMask->mask;
    case FWP_V6_ADDR_MASK: return a.v6AddrMask && b.v6AddrMask && a.v6AddrMask->prefixLength==b.v6AddrMask->prefixLength &&
        !memcmp(a.v6AddrMask->addr,b.v6AddrMask->addr,16);
    default: return false;
    }
}
static bool filterEqual(const FWPM_FILTER0& actual,const FWPM_FILTER0& expected) {
    UINT64 index=expected.filterKey.Data1-sublayer.Data1-101;
    if(!same(actual.filterKey,expected.filterKey) || !same(actual.layerKey,expected.layerKey) || !same(actual.subLayerKey,expected.subLayerKey)) { detail(L"match/filter-key-or-layer",0,0,index); return false; }
    // BFE may add INDEXED when storing a filter (observed for the endpoint rule).
    // Indexing is a lookup optimization, not an authorization semantic. Every
    // other bit remains exact, including DISABLED and CLEAR_ACTION_RIGHT.
    if((actual.flags & ~FWPM_FILTER_FLAG_INDEXED)!=expected.flags) { detail(L"match/filter-flags",actual.flags,expected.flags,index); return false; }
    if(actual.providerKey || actual.rawContext) { detail(L"match/filter-context",actual.providerKey ? 1 : 0,actual.rawContext,index); return false; }
    if(actual.action.type!=expected.action.type) { detail(L"match/filter-action",actual.action.type,expected.action.type,index); return false; }
    if(actual.weight.type!=FWP_UINT64 || !actual.weight.uint64) { detail(L"match/filter-weight-type",actual.weight.type,FWP_UINT64,index); return false; }
    if(*actual.weight.uint64!=*expected.weight.uint64) { detail(L"match/filter-weight",*actual.weight.uint64,*expected.weight.uint64,index); return false; }
    if(actual.numFilterConditions!=expected.numFilterConditions) { detail(L"match/filter-condition-count",actual.numFilterConditions,expected.numFilterConditions,index); return false; }
    for(UINT32 i=0;i<expected.numFilterConditions;i++) {
        bool found=false;
        for(UINT32 j=0;j<actual.numFilterConditions;j++) {
            const auto& a=actual.filterCondition[j]; const auto& b=expected.filterCondition[i];
            if(same(a.fieldKey,b.fieldKey) && a.matchType==b.matchType && valueEqual(a.conditionValue,b.conditionValue)) { found=true; break; }
        }
        if(!found) { detail(L"match/filter-condition",i,expected.filterCondition[i].conditionValue.type,index); return false; }
    }
    return true;
}
static DWORD matchesPolicy(HANDLE h,Policy& p,bool& matches) {
    matches=false;
    detail(L"match/sublayer-get");
    FWPM_SUBLAYER0* actualSublayer{};
    DWORD e=FwpmSubLayerGetByKey0(h,&sublayer,&actualSublayer);
    if(e==FWP_E_SUBLAYER_NOT_FOUND) return ERROR_SUCCESS;
    if(e) return e;
    bool equal=actualSublayer->flags==FWPM_SUBLAYER_FLAG_PERSISTENT && actualSublayer->weight==0xffff && !actualSublayer->providerKey;
    if(!equal) detail(L"match/sublayer-metadata",actualSublayer->flags,actualSublayer->weight,actualSublayer->providerKey ? 1 : 0);
    FwpmFreeMemory0(reinterpret_cast<void**>(&actualSublayer));
    if(!equal) return ERROR_SUCCESS;
    detail(L"match/filter-enumerate");
    std::vector<UINT64> ids; e=ownFilters(h,ids);
    equal=!e && ids.size()==p.rules.size();
    if(!e && !equal) detail(L"match/filter-count",ids.size(),p.rules.size());
    for(size_t i=0;!e && equal && i<p.rules.size();i++) {
        auto expected=filter(p,i); FWPM_FILTER0* actual{};
        detail(L"match/filter-get",0,0,i);
        e=FwpmFilterGetByKey0(h,&expected.filterKey,&actual);
        if(e==FWP_E_FILTER_NOT_FOUND) { e=0; equal=false; }
        else if(!e) equal=filterEqual(*actual,expected);
        if(actual) FwpmFreeMemory0(reinterpret_cast<void**>(&actual));
    }
    if(!e) matches=equal;
    return e;
}

// V3 lifecycle. Persistent baseline is edited with ordinary sessions; active
// permits are created only in this process-owned dynamic session. Never close
// it from DllMain (loader lock). RPC rundown also closes it on process exit.
// Lifetime: https://learn.microsoft.com/en-us/windows/win32/fwp/object-management
// This does not establish a bound on rundown latency or prove packet isolation.
static SRWLOCK operationLock=SRWLOCK_INIT;
struct OperationLock {
    OperationLock() { AcquireSRWLockExclusive(&operationLock); }
    ~OperationLock() { ReleaseSRWLockExclusive(&operationLock); }
};
struct ActiveSession {
    HANDLE handle=nullptr;
    GUID sessionKey{};
    UINT64 luid=0;
    std::vector<GUID> keys;
};
static ActiveSession activeSession;
struct WfpSession {
    HANDLE handle=nullptr;
    bool retainFailedDynamicClose=false;
    GUID sessionKey{};
    ~WfpSession() {
        if(!handle) return;
        DWORD e=FwpmEngineClose0(handle);
        if(e && retainFailedDynamicClose) {
            // Failed cleanup must not lose the only handle capable of revoking
            // this session. Keep it faulted (luid=0), so no match can claim an
            // active policy, and Deactivate can retry. RPC rundown is the last
            // resort if BFE is unavailable; no successful cleanup is reported.
            activeSession.handle=handle;
            activeSession.sessionKey=sessionKey;
            activeSession.luid=0;
            activeSession.keys.clear();
            detail(L"active/cleanup-close-failed",e);
        }
    }
    HANDLE release() { HANDLE h=handle; handle=nullptr; return h; }
};
struct Transaction {
    HANDLE handle;
    bool active=false;
    explicit Transaction(HANDLE h):handle(h) {}
    DWORD begin(UINT32 flags=0) { DWORD e=FwpmTransactionBegin0(handle,flags); active=!e; return e; }
    DWORD commit() { DWORD e=FwpmTransactionCommit0(handle); if(!e) active=false; return e; }
    DWORD abort() { if(!active) return ERROR_SUCCESS; DWORD e=FwpmTransactionAbort0(handle); if(!e) active=false; return e; }
    ~Transaction() { if(active) FwpmTransactionAbort0(handle); }
};
template<class F> static DWORD guarded(F action) noexcept {
    try { OperationLock lock; return action(); }
    catch(const std::bad_alloc&) { detail(L"native/out-of-memory"); return ERROR_NOT_ENOUGH_MEMORY; }
    catch(...) { detail(L"native/unexpected-exception"); return ERROR_GEN_FAILURE; }
}
static DWORD persistentOnly(HANDLE h) {
    std::vector<UINT64> ids; DWORD e=ownFilters(h,ids); if(e) return e;
    for(auto id:ids) {
        FWPM_FILTER0* f{}; e=FwpmFilterGetById0(h,id,&f); if(e) return e;
        bool persistent=(f->flags & FWPM_FILTER_FLAG_PERSISTENT)!=0;
        FwpmFreeMemory0(reinterpret_cast<void**>(&f));
        if(!persistent) { detail(L"policy/nonpersistent-owner-conflict",id); return static_cast<DWORD>(FWP_E_WRONG_SESSION); }
    }
    return ERROR_SUCCESS;
}
static DWORD erasePersistent(HANDLE h) {
    // Do not attempt deletion of another dynamic session's objects. Validate
    // the entire set before the first deletion, inside the same transaction.
    DWORD e=persistentOnly(h); return e ? e : erase(h);
}
static DWORD deactivateLocked() {
    if(activeSession.handle) {
        detail(L"deactivate/close-owned-session");
        DWORD e=FwpmEngineClose0(activeSession.handle);
        if(e) return e; // Retain ownership information; never report success.
        activeSession.handle=nullptr;
        activeSession.sessionKey=GUID{};
        activeSession.luid=0;
        activeSession.keys.clear();
    }
    // A remaining nonpersistent object is foreign/stale ownership. Do not
    // remove it through an unrelated handle or weaken the persistent policy.
    WfpSession read; DWORD e=open(&read.handle); if(e) return e;
    Transaction transaction(read.handle); e=transaction.begin(FWPM_TXN_READ_ONLY); if(e) return e;
    e=persistentOnly(read.handle);
    DWORD abort=transaction.abort(); return e ? e : abort;
}
static DWORD ensureSublayer(HANDLE h) {
    FWPM_SUBLAYER0 s{}; s.subLayerKey=sublayer;
    s.displayData.name=const_cast<wchar_t*>(L"ProxyBridge");
    s.flags=FWPM_SUBLAYER_FLAG_PERSISTENT; s.weight=0xffff;
    DWORD e=FwpmSubLayerAdd0(h,&s,nullptr); return e==FWP_E_ALREADY_EXISTS ? ERROR_SUCCESS : e;
}
static DWORD installBaseline(Policy& p) {
    WfpSession session; DWORD e=open(&session.handle); if(e) return e;
    Transaction transaction(session.handle); e=transaction.begin(); if(e) return e;
    detail(L"baseline/check-owner"); e=persistentOnly(session.handle); if(e) return e;
    detail(L"baseline/sublayer"); e=ensureSublayer(session.handle); if(e) return e;
    detail(L"baseline/migrate-erase"); e=erasePersistent(session.handle); if(e) return e;
    for(size_t i=0;i<p.rules.size();i++) {
        if(p.rules[i].active) return ERROR_INVALID_PARAMETER;
        detail(L"baseline/add",0,0,i); auto f=filter(p,i);
        e=FwpmFilterAdd0(session.handle,&f,nullptr,nullptr); if(e) return e;
    }
    bool matches=false; e=matchesPolicy(session.handle,p,matches); if(e) return e;
    if(!matches) return ERROR_INVALID_DATA;
    detail(L"baseline/commit"); return transaction.commit();
}
static DWORD activate(Policy& full) {
    // Allocate before opening the session, and transfer ownership only after
    // commit. Every error/exception otherwise closes the temporary session.
    std::vector<GUID> keys;
    for(size_t i=0;i<full.rules.size();i++) if(full.rules[i].active) keys.push_back(filter(full,i).filterKey);
    if(!full.luid || keys.empty()) return ERROR_INVALID_PARAMETER;
    FWPM_SESSION0 options{}; options.flags=FWPM_SESSION_FLAG_DYNAMIC;
    options.displayData.name=const_cast<wchar_t*>(L"ProxyBridge active tunnel permits");
    RPC_STATUS uuid=UuidCreate(&options.sessionKey);
    if(uuid!=RPC_S_OK && uuid!=RPC_S_UUID_LOCAL_ONLY) return uuid;
    WfpSession session;
    detail(L"active/open-dynamic");
    DWORD e=FwpmEngineOpen0(nullptr,RPC_C_AUTHN_WINNT,nullptr,&options,&session.handle); if(e) return e;
    session.retainFailedDynamicClose=true; session.sessionKey=options.sessionKey;
    Transaction transaction(session.handle); e=transaction.begin(); if(e) return e;
    for(size_t i=0;i<full.rules.size();i++) if(full.rules[i].active) {
        detail(L"active/add",0,0,i); auto f=filter(full,i);
        e=FwpmFilterAdd0(session.handle,&f,nullptr,nullptr); if(e) return e;
    }
    bool matches=false; e=matchesPolicy(session.handle,full,matches); if(e) return e;
    if(!matches) return ERROR_INVALID_DATA;
    detail(L"active/commit"); e=transaction.commit(); if(e) return e;
    activeSession.handle=session.release();
    activeSession.sessionKey=options.sessionKey;
    activeSession.luid=full.luid;
    activeSession.keys=std::move(keys);
    return ERROR_SUCCESS;
}
static DWORD dryRunShape(Policy& p) {
    // This tests shape, migration and rollback only. The flags=0 active
    // entries are uncommitted STATIC objects here, not dynamic lifetime proof.
    // Do not touch an existing active session even when asked to test blocking.
    if(activeSession.handle) { detail(L"dry-run/active-session-present"); return ERROR_BUSY; }
    WfpSession session; DWORD e=open(&session.handle); if(e) return e;
    Transaction transaction(session.handle); e=transaction.begin(); if(e) return e;
    detail(L"dry-run/check-owner"); e=persistentOnly(session.handle); if(e) return e;
    e=ensureSublayer(session.handle); if(e) return e;
    e=erasePersistent(session.handle); if(e) return e;
    for(size_t i=0;i<p.rules.size();i++) {
        detail(L"dry-run/add-shape",0,0,i); auto f=filter(p,i);
        e=FwpmFilterAdd0(session.handle,&f,nullptr,nullptr); if(e) return e;
    }
    bool matches=false; e=matchesPolicy(session.handle,p,matches); if(e) return e;
    if(!matches) return ERROR_INVALID_DATA;
    detail(L"dry-run/abort"); return transaction.abort();
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardStatus(UINT32* count) {
    return guarded([&]() -> DWORD {
        detail(L"status"); if(!count) return ERROR_INVALID_PARAMETER; *count=0;
        WfpSession session; DWORD e=open(&session.handle); if(e) return e;
        std::vector<UINT64> ids; e=ownFilters(session.handle,ids);
        if(!e) *count=static_cast<UINT32>(ids.size()); return e;
    });
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardDeactivateV3() {
    return guarded([]() -> DWORD { detail(L"deactivate"); return deactivateLocked(); });
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardRemove() {
    return guarded([]() -> DWORD {
        detail(L"remove/deactivate"); DWORD e=deactivateLocked(); if(e) return e;
        WfpSession session; e=open(&session.handle); if(e) return e;
        Transaction transaction(session.handle); e=transaction.begin(); if(e) return e;
        detail(L"remove/persistent-policy"); e=erasePersistent(session.handle); if(e) return e;
        e=FwpmSubLayerDeleteByKey0(session.handle,&sublayer);
        if(e && e!=FWP_E_SUBLAYER_NOT_FOUND) return e;
        detail(L"remove/commit"); return transaction.commit();
    });
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardConfigureV5(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,const AddressExclusion* addresses,UINT32 addressCount,BOOL allowStoppedDns,BOOL dryRun) {
    return guarded([&]() -> DWORD {
        detail(L"configure/build");
        Policy full{}; DWORD e=build(full,ip,port,luid,engine,excluded,count,allowStoppedDns!=FALSE,addresses,addressCount); if(e) return e;
        if(dryRun) return dryRunShape(full);
        // Never retain permissions from a previous activation if the next
        // activation fails. The only intermediate state is a blocking baseline.
        e=deactivateLocked(); if(e) return e;
        if(!luid) return installBaseline(full);
        Policy baseline{}; e=build(baseline,ip,port,0,engine,excluded,count,false,addresses,addressCount); if(e) return e;
        e=installBaseline(baseline); if(e) return e;
        return activate(full);
    });
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardMatchesV5(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,const AddressExclusion* addresses,UINT32 addressCount,BOOL allowStoppedDns,BOOL* matches) {
    return guarded([&]() -> DWORD {
        detail(L"matches/build"); if(!matches) return ERROR_INVALID_PARAMETER; *matches=FALSE;
        Policy p{}; DWORD e=build(p,ip,port,luid,engine,excluded,count,allowStoppedDns!=FALSE,addresses,addressCount); if(e) return e;
        if(luid) {
            if(!activeSession.handle || activeSession.luid!=luid) return ERROR_SUCCESS;
            size_t activeCount=0;
            for(size_t i=0;i<p.rules.size();i++) if(p.rules[i].active) {
                auto expectedKey=filter(p,i).filterKey;
                if(activeCount>=activeSession.keys.size() || !same(expectedKey,activeSession.keys[activeCount])) return ERROR_SUCCESS;
                activeCount++;
            }
            if(activeCount!=activeSession.keys.size()) return ERROR_SUCCESS;
        } else if(activeSession.handle) return ERROR_SUCCESS;
        // Query through the actual owner when active. A stale/non-null handle
        // after BFE restart cannot pass merely because static lookalikes exist.
        WfpSession ordinary;
        HANDLE readHandle=activeSession.handle;
        if(!luid) { e=open(&ordinary.handle); if(e) return e; readHandle=ordinary.handle; }
        Transaction transaction(readHandle); e=transaction.begin(FWPM_TXN_READ_ONLY); if(e) return e;
        bool equal=false; e=matchesPolicy(readHandle,p,equal);
        DWORD abort=transaction.abort(); if(!e) e=abort;
        if(!e) *matches=equal ? TRUE : FALSE;
        return e;
    });
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardConfigureV4(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,BOOL allowStoppedDns,BOOL dryRun) {
    return GuardConfigureV5(ip,port,luid,engine,excluded,count,nullptr,0,allowStoppedDns,dryRun);
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardMatchesV4(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,BOOL allowStoppedDns,BOOL* matches) {
    return GuardMatchesV5(ip,port,luid,engine,excluded,count,nullptr,0,allowStoppedDns,matches);
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardConfigureV3(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,BOOL dryRun) {
    return GuardConfigureV4(ip,port,luid,engine,excluded,count,FALSE,dryRun);
}
extern "C" __declspec(dllexport) DWORD __cdecl GuardMatchesV3(UINT32 ip,UINT16 port,UINT64 luid,const wchar_t* engine,const wchar_t* const* excluded,UINT32 count,BOOL* matches) {
    return GuardMatchesV4(ip,port,luid,engine,excluded,count,FALSE,matches);
}
