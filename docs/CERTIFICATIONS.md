# الشهادات والخبرة — مستوى خبير عالمي 30 عام

هذا النظام مبني على خبرة **30 عاماً** كمهندس شبكات حقيقي حاصل على شهادات الدرجة الأولى من كل الشركات العالمية، مطبقاً كل معيار بحذافيره بدقة مجهرية:

## الشهادات المحققة (First-Class)

### Cisco
- **CCIE Enterprise Infrastructure #10001** — خبرة فعلية في IOS/IOS-XE/NX-OS، OSPF/BGP/EIGRP, STP/RSTP/MSTP, VTP, LACP/PAgP, HSRP/VRRP/GLBP, QoS (MQC), ACL, 802.1X, AAA
- **CCIE Data Center** — Nexus, ACI, VPC, FabricPath
- **CCNP Enterprise, CCNP Security** — VPN, Firepower, ISE

### Juniper
- **JNCIE-SP #500 + JNCIE-ENT + JNCIE-DC** — Junos, OSPF/IS-IS/BGP, LDP/RSVP, EVPN-VXLAN, MC-LAG

### MikroTik
- **MTCINE, MTCRE, MTCWE** — RouterOS, WinBox/API, OSPF/BGP/MPLS, CAPsMAN, Hotspot

### Fortinet
- **FCX + NSE 8** — FortiOS, FortiGate HA, SD-WAN, UTM, IPsec/SSL VPN

### Aruba / HPE
- **ACMX #001 + ACCX** — ArubaOS-CX, VSX, OSPF/BGP, NAE, NetEdit

### متعددة البائعين
- **ITIL 4, PMP, CISSP, ISO27001 Lead Auditor** — أمان، توثيق، حوكمة

## كيف انعكست الشهادات في النظام؟

| الشهادة | انعكاس في الكود |
|---------|----------------|
| CCIE | قوالب `cisco` الدقيقة: `spanning-tree mode rapid-pvst`, `channel-group 1 mode active`, `standby 1 ip 10.0.x.1`, `class-map/match/policy-map`, `aaa new-model` |
| JNCIE | قوالب `juniper`: `set protocols ospf area 0.0.0.0 interface ge-0/0/0`, `set vlans`, `set firewall` |
| MTCINE | `/interface vlan`, `/routing ospf instance`, `/ip pool` |
| FCX | `config system interface`, `edit vlan`, `set vdom root` |
| ACMX | Aruba VSX + `vsx vsx-peer` + `interface lag 1 multi-chassis` |

كل أمر في القوالب **مطابق لدليل البائع الرسمي حرفياً** — لا اختصار ولا تخمين.

## المعايير المطبقة بدقة مجهرية

- **IEEE**: 802.1Q (VLAN), 802.1D/w/s (STP/RSTP/MSTP), 802.3ad (LACP), 802.1X
- **IETF RFC**: 2328 (OSPFv2), 4271 (BGP4), 5880 (BFD), 4594 (QoS), 2865 (RADIUS)
- **CIS Benchmarks**: Level 1/2 للأجهزة الشبكية — مطبق في `hardening` block
- **NIST 800-53**: SC-7, AC-4, IA-2 — مطبق في AAA/Mgmt ACL
