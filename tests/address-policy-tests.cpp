// Pure builder, synthetic-flow interpreter and comparator checks. This program
// never opens BFE, acquires the app mutex, installs filters, or sends traffic.
// FwpmGetAppIdFromFileName only converts the supplied existing executable path.
#include "../native/guard.cpp"
#include <cstddef>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>

namespace address_audit {
static int passed=0;
static void require(bool condition,const char* message) { if(!condition) throw std::runtime_error(message); }
static void test(const char* name,const std::function<void()>& action) {
    action(); ++passed; std::cout << "PASS: " << name << std::endl;
}
static AddressExclusion entry(const wchar_t* ip,UINT32 prefix,UINT32 port=0) {
    AddressExclusion a{}; a.family=wcschr(ip,L':') ? 6 : 4; a.prefixLength=prefix; a.port=port;
    require(InetPtonW(a.family==4 ? AF_INET : AF_INET6,ip,a.address)==1,"invalid synthetic address");
    return a;
}
static void buildPolicy(Policy& p,const wchar_t* engine,const std::vector<AddressExclusion>& addresses,UINT64 luid=0,bool dns=false) {
    DWORD e=build(p,0xc000020a,1080,luid,engine,nullptr,0,dns,addresses.data(),static_cast<UINT32>(addresses.size()));
    if(e) throw std::runtime_error("policy builder failed, code="+std::to_string(e));
}
struct Flow {
    AddressExclusion destination;
    UINT16 port;
    UINT8 protocol;
    bool inbound=false;
};
static bool matches(const FWPM_FILTER_CONDITION0& c,const Flow& flow) {
    const auto& v=c.conditionValue;
    bool result=false;
    if(same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_ADDRESS)) {
        if(v.type==FWP_V4_ADDR_MASK && flow.destination.family==4) {
            const auto* b=flow.destination.address;
            UINT32 ip=(static_cast<UINT32>(b[0])<<24)|(static_cast<UINT32>(b[1])<<16)|(static_cast<UINT32>(b[2])<<8)|b[3];
            result=(ip & v.v4AddrMask->mask)==v.v4AddrMask->addr;
        } else if(v.type==FWP_V6_ADDR_MASK && flow.destination.family==6) {
            result=true;
            for(unsigned bit=0;bit<v.v6AddrMask->prefixLength;bit++) {
                unsigned mask=1u<<(7-bit%8);
                if((flow.destination.address[bit/8]&mask)!=(v.v6AddrMask->addr[bit/8]&mask)) result=false;
            }
        } else if(v.type==FWP_UINT32 && flow.destination.family==4) {
            const auto* b=flow.destination.address;
            result=((static_cast<UINT32>(b[0])<<24)|(static_cast<UINT32>(b[1])<<16)|(static_cast<UINT32>(b[2])<<8)|b[3])==v.uint32;
        }
    } else if(same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT)) {
        require(v.type==FWP_UINT16,"port condition has wrong type"); result=v.uint16==flow.port;
    } else if(same(c.fieldKey,FWPM_CONDITION_IP_PROTOCOL)) {
        require(v.type==FWP_UINT8,"protocol condition has wrong type"); result=v.uint8==flow.protocol;
    } else if(same(c.fieldKey,FWPM_CONDITION_ALE_APP_ID) || same(c.fieldKey,FWPM_CONDITION_FLAGS) ||
        same(c.fieldKey,FWPM_CONDITION_IP_NEXTHOP_INTERFACE) || same(c.fieldKey,FWPM_CONDITION_IP_LOCAL_INTERFACE) ||
        same(c.fieldKey,FWPM_CONDITION_IP_ARRIVAL_INTERFACE)) {
        // Synthetic flows use an unrelated app, a physical interface, no
        // loopback and no TUN reauthorization. These existing permits cannot match.
        return false;
    } else throw std::runtime_error("unknown policy condition in synthetic oracle");
    require(c.matchType==FWP_MATCH_EQUAL || c.matchType==FWP_MATCH_NOT_EQUAL,"unexpected address match mode");
    return c.matchType==FWP_MATCH_NOT_EQUAL ? !result : result;
}
static bool permitted(const Policy& p,const Flow& flow) {
    const GUID& layer=flow.inbound
        ? (flow.destination.family==4 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6)
        : (flow.destination.family==4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6);
    UINT64 weight=0; bool allow=false;
    for(const auto& r:p.rules) {
        if(!same(r.layer,layer) || !std::all_of(r.conditions.begin(),r.conditions.end(),[&](const auto& c){return matches(c,flow);})) continue;
        if(r.weight>=weight) { weight=r.weight; allow=r.action==FWP_ACTION_PERMIT; }
    }
    return allow;
}
static void run(const wchar_t* engine) {
    test("V5 ABI size and offsets",[] {
        require(sizeof(AddressExclusion)==28 && offsetof(AddressExclusion,family)==0 && offsetof(AddressExclusion,prefixLength)==4 &&
            offsetof(AddressExclusion,port)==8 && offsetof(AddressExclusion,address)==12,"address ABI layout changed");
    });
    std::vector<AddressExclusion> addresses={entry(L"192.168.1.0",24),entry(L"198.51.100.0",25,8443),
        entry(L"203.0.113.9",32,443),entry(L"fd00::",64,8080),entry(L"2001:db8::",32)};
    Policy stopped{},active{},old{};
    buildPolicy(stopped,engine,addresses); buildPolicy(active,engine,addresses,0x10000); buildPolicy(old,engine,{});
    test("address filters are persistent, outbound, exact protocol and unique slots",[&] {
        size_t count=0; std::vector<GUID> keys;
        for(size_t i=0;i<stopped.rules.size();i++) {
            auto f=filter(stopped,i);
            require(std::none_of(keys.begin(),keys.end(),[&](const GUID& k){return same(k,f.filterKey);}),"duplicate filter key"); keys.push_back(f.filterKey);
            const auto& r=stopped.rules[i];
            if(r.slot<2048) continue;
            ++count;
            require(r.slot<2176 && !r.active && f.flags==FWPM_FILTER_FLAG_PERSISTENT && r.action==FWP_ACTION_PERMIT &&
                r.weight==100 && r.conditions.size()==3,"address lifetime, scope or condition count differs");
            require(same(r.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V4)||same(r.layer,FWPM_LAYER_ALE_AUTH_CONNECT_V6),"address opened inbound layer");
            bool address=false,port=false,protocol=false;
            for(const auto& c:r.conditions) {
                address|=same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_ADDRESS) && c.matchType==FWP_MATCH_EQUAL &&
                    (c.conditionValue.type==FWP_V4_ADDR_MASK || c.conditionValue.type==FWP_V6_ADDR_MASK);
                port|=same(c.fieldKey,FWPM_CONDITION_IP_REMOTE_PORT) && c.conditionValue.type==FWP_UINT16 &&
                    ((c.matchType==FWP_MATCH_NOT_EQUAL && c.conditionValue.uint16==53) || (c.matchType==FWP_MATCH_EQUAL && c.conditionValue.uint16!=53));
                protocol|=same(c.fieldKey,FWPM_CONDITION_IP_PROTOCOL) && c.matchType==FWP_MATCH_EQUAL && c.conditionValue.type==FWP_UINT8 &&
                    (c.conditionValue.uint8==IPPROTO_TCP || c.conditionValue.uint8==IPPROTO_UDP);
            }
            require(address && port && protocol,"missing destination, port or protocol guard");
        }
        require(count==addresses.size()*2 && stopped.rules.size()==old.rules.size()+count,"unexpected broad rules added");
    });
    auto flow=[&](const char* name,const wchar_t* ip,UINT16 port,UINT8 protocol,bool expected,bool inbound=false) {
        test(name,[&] {
            auto destination=entry(ip,wcschr(ip,L':') ? 128u : 32u);
            Flow f{destination,port,protocol,inbound};
            require(permitted(stopped,f)==expected && permitted(active,f)==expected,"synthetic policy decision differs");
        });
    };
    flow("LAN first IPv4 TCP permitted",L"192.168.1.0",80,IPPROTO_TCP,true);
    flow("LAN last IPv4 UDP permitted",L"192.168.1.255",65535,IPPROTO_UDP,true);
    flow("IPv4 before LAN blocked",L"192.168.0.255",80,IPPROTO_TCP,false);
    flow("IPv4 after LAN blocked",L"192.168.2.0",80,IPPROTO_TCP,false);
    flow("LAN TCP DNS blocked",L"192.168.1.1",53,IPPROTO_TCP,false);
    flow("LAN UDP DNS blocked",L"192.168.1.1",53,IPPROTO_UDP,false);
    flow("LAN unsupported protocol blocked",L"192.168.1.1",80,IPPROTO_ICMP,false);
    flow("LAN unsolicited inbound blocked",L"192.168.1.1",80,IPPROTO_TCP,false,true);
    flow("CIDR plus port permitted",L"198.51.100.127",8443,IPPROTO_TCP,true);
    flow("right CIDR wrong port blocked",L"198.51.100.127",443,IPPROTO_TCP,false);
    flow("right port wrong CIDR blocked",L"198.51.100.128",8443,IPPROTO_TCP,false);
    flow("host plus port UDP permitted",L"203.0.113.9",443,IPPROTO_UDP,true);
    flow("host cannot borrow another rule port",L"203.0.113.9",8443,IPPROTO_TCP,false);
    flow("IPv6 ULA port match permitted",L"fd00::ffff",8080,IPPROTO_TCP,true);
    flow("IPv6 ULA wrong port blocked",L"fd00::ffff",443,IPPROTO_TCP,false);
    flow("IPv6 outside prefix blocked",L"fd00:0:0:1::1",8080,IPPROTO_TCP,false);
    flow("IPv6 global prefix final address permitted",L"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",443,IPPROTO_TCP,true);
    flow("IPv6 adjacent prefix blocked",L"2001:db9::",443,IPPROTO_TCP,false);
    flow("IPv6 DNS blocked",L"2001:db8::53",53,IPPROTO_UDP,false);
    flow("IPv6 unsolicited inbound blocked",L"fd00::1",8080,IPPROTO_TCP,false,true);
    test("address-only stopped DNS request adds no resolver permission",[&] {
        Policy requested{}; buildPolicy(requested,engine,addresses,0,true);
        require(requested.rules.size()==stopped.rules.size() && requested.dns.empty() && requested.dnsIdentity.data==nullptr,
            "address-only settings enabled shared stopped DNS");
        for(size_t i=0;i<stopped.rules.size();i++) require(filterEqual(filter(requested,i),filter(stopped,i)),"stopped DNS changed address policy");
    });
    test("empty V5 address list preserves old builder policy",[&] {
        Policy legacy{}; require(build(legacy,0xc000020a,1080,0,engine,nullptr,0)==ERROR_SUCCESS,"legacy builder failed");
        require(legacy.rules.size()==old.rules.size(),"empty V5 changed policy count");
        for(size_t i=0;i<old.rules.size();i++) require(filterEqual(filter(legacy,i),filter(old,i)),"empty V5 changed existing filter");
    });
    test("max64 address capacity keeps all mask pointers and key spaces valid",[&] {
        std::vector<AddressExclusion> many;
        for(UINT32 i=0;i<64;i++) { auto a=entry(L"198.51.100.0",32,80); a.address[3]=static_cast<BYTE>(i); many.push_back(a); }
        Policy full{}; buildPolicy(full,engine,many,0x10000);
        for(UINT32 i=0;i<64;i++) require(permitted(full,{many[i],80,IPPROTO_TCP}),"mask pointer invalid after vector growth");
        std::vector<GUID> keys;
        for(size_t i=0;i<full.rules.size();i++) { auto f=filter(full,i);
            require(std::none_of(keys.begin(),keys.end(),[&](const GUID& k){return same(k,f.filterKey);}),"active/persistent slot collision"); keys.push_back(f.filterKey); }
    });
    test("zero-prefix IPv4 and IPv6 rules still exclude DNS and non-TCP/UDP",[&] {
        Policy all{}; buildPolicy(all,engine,{entry(L"0.0.0.0",0),entry(L"::",0)});
        for(auto ip:{L"198.51.100.1",L"2001:db8::1"}) {
            auto a=entry(ip,wcschr(ip,L':') ? 128u : 32u);
            require(permitted(all,{a,443,IPPROTO_TCP}) && !permitted(all,{a,53,IPPROTO_TCP}) && !permitted(all,{a,443,IPPROTO_ICMP}),"zero-prefix scope widened");
        }
    });
    test("native malformed addresses fail before any policy installation",[&] {
        auto invalid=[&](AddressExclusion a) { Policy bad{};
            require(build(bad,0xc000020a,1080,0,engine,nullptr,0,false,&a,1)==ERROR_INVALID_PARAMETER,"invalid native address accepted"); };
        auto a=entry(L"192.168.1.0",24); a.family=5; invalid(a);
        a=entry(L"192.168.1.0",24); a.prefixLength=33; invalid(a);
        a=entry(L"fd00::",64); a.prefixLength=129; invalid(a);
        a=entry(L"192.168.1.1",24); invalid(a);
        a=entry(L"fd00::1",64); invalid(a);
        a=entry(L"192.168.1.0",24); a.address[15]=1; invalid(a);
        a=entry(L"::ffff:192.168.1.1",128); invalid(a);
        a=entry(L"192.168.1.0",24,53); invalid(a);
        a=entry(L"192.168.1.0",24,65536); invalid(a);
        Policy nullList{},tooMany{};
        require(build(nullList,0xc000020a,1080,0,engine,nullptr,0,false,nullptr,1)==ERROR_INVALID_PARAMETER,"null counted list accepted");
        require(build(tooMany,0xc000020a,1080,0,engine,nullptr,0,false,&a,65)==ERROR_INVALID_PARAMETER,"excess count accepted");
    });
    test("mask comparator and filter matcher reject weakened address conditions",[&] {
        for(size_t i=0;i<stopped.rules.size();i++) {
            if(stopped.rules[i].slot<2048) continue;
            auto expected=filter(stopped,i); auto actual=expected;
            auto conditions=stopped.rules[i].conditions; actual.filterCondition=conditions.data();
            require(filterEqual(actual,expected),"unchanged address filter rejected");
            auto& remote=conditions[0].conditionValue;
            FWP_V4_ADDR_AND_MASK v4{}; FWP_V6_ADDR_AND_MASK v6{};
            if(remote.type==FWP_V4_ADDR_MASK) { v4=*remote.v4AddrMask; v4.mask>>=1; remote.v4AddrMask=&v4; }
            else { v6=*remote.v6AddrMask; --v6.prefixLength; remote.v6AddrMask=&v6; }
            require(!filterEqual(actual,expected),"weakened mask accepted");
            conditions=stopped.rules[i].conditions; actual.filterCondition=conditions.data(); conditions[1].conditionValue.uint16=54;
            require(!filterEqual(actual,expected),"changed port accepted");
            conditions=stopped.rules[i].conditions; actual.filterCondition=conditions.data(); conditions[1].matchType=FWP_MATCH_GREATER;
            require(!filterEqual(actual,expected),"changed port match mode accepted");
            conditions=stopped.rules[i].conditions; actual.filterCondition=conditions.data(); conditions.pop_back(); actual.numFilterConditions=static_cast<UINT32>(conditions.size());
            require(!filterEqual(actual,expected),"removed protocol accepted");
        }
    });
}
}

int wmain(int argc,wchar_t** argv) {
    try {
        if(argc!=2) throw std::runtime_error("usage: address-policy-tests.exe <existing-engine.exe>");
        address_audit::run(argv[1]);
        std::cout << "SUMMARY: " << address_audit::passed << " PASS, 0 FAIL; no BFE session or traffic." << std::endl;
        std::cout << "SKIP: live WFP acceptance, TUN routing, existing flows and antivirus behavior require separate coordinator tests." << std::endl;
        return 0;
    } catch(const std::exception& e) { std::cout << "FAIL: " << e.what() << std::endl; return 1; }
}
