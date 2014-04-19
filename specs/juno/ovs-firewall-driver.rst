..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

========================================================================
Open vSwitch-based Security Groups: OVS Implementation of FirewallDriver
========================================================================

Launchpad blueprint:

https://blueprints.launchpad.net/neutron/+spec/ovs-firewall-driver


Problem description
===================

To support the security groups extension in the OVS neutron agent through OVS
flows using the existing OVS library with feature parity to the existing
iptables-based implementations. In Icehouse, the existing openvswitch plugin is
being deprecated, so the blueprint is compatible with the ML2 plugin with the
openvswitch mechanism driver.

We won't have behavioral parity with iptables, due to OVS lacking connection
tracking. This blueprint represents an "80%" solution we can make available to
providers today as opposed to waiting until 2015 when connection tracking is
available in OVS[5]. In the proposed implementation, the OVS FirewallDriver is
stateless for non-TCP flows and cannot emulate iptables's RELATED feature.


Proposed change
===============

1. ovs_neutron_agent related changes

ovs_neutron_agent has some obstacles in making an Open vSwitch-based security
groups firewall implementation work.

* Firewall is invoked before local VLAN is assigned

  Without the local VLAN for a given Neutron network, an OVS-based firewall
  will not know where to forward the packet on the allow path.

* Agent removes all flows at initialization

  Upon startup the agent removes all flows on all relevant bridges. This issue
  is outside the scope of this particular blueprint and is being covered by
  blueprint neutron-agent-soft-restart.

* OVS crashes

  See https://bugs.launchpad.net/neutron/+bug/1290486

* Agent removes a VIF's flows on port_bound

  Related to the previous point, all the flows on the integration bridge
  belonging to a vif's OpenFlow port are removed. Since the firewall is invoked
  to setup port filters before connectivity is established (i.e. before
  port_bound is called) this defeats the firewall. To solve this issue, I
  propose using a distinct cookie on flows that belong to the firewall and a
  separate, distinct cookie on flows that belong to the agent. This will
  require OVS version 1.5.0+ to delete flows based on a cookie (current version
  in XenServer 6.2 and Ubuntu P/Q-release is 1.4.6).


2. Extension of security groups extension

To implement a performant OVS-based security groups solution in Neutron today,
source port matching is a required addition to the security groups extension
API.

Following through with the 'stateless ACLs with tcp_flags=ack' approach as
discussed in the Alternatives section below, UDP clients on the instance will
need explicit security group rules to match source IP address and source port.

Example 1. A remote UDP client connecting to an instance UDP server::
   A. nw_src=$remote_ip, tp_src=random, nw_dst=$instance_ip, tp_dst=9987
   B. nw_src=$instance_ip, tp_src=9987, nw_dst=$remote_ip, tp_src=random

In the case of the instance being a UDP server and default security groups
already allowing all egress, adding a rule to allow ingress on UDP destination
port 9987 will behave as expected.

Example 2. An instance UDP client connecting to a remote UDP server::
   C. nw_src=$instance_ip, tp_src=random, nw_dst=$remote_ip, tp_dst=9987
   D. nw_src=$remote_ip, tp_src=9987, nw_dst=$instance_ip, tp_dst=random

In the case of the instance being a UDP client and default security groups
already allowing all egress, we will need a new security group rule to allow
ingress from source port 9987 from the remote UDP server in a stateless
firewall. This is different behavior than the iptables-based stateful firewall
implementation because iptables is able to add the reverse flow in its state
table for a specific timeout length when it initially sees flow C.

In security groups, we will need an additional rule that will define flow D
(remote UDP server’s IP address, UDP source port 9987, and of course the
instance’s IP address). However, if you look at the security groups API as it
is today[3], you will see there is no match for source port (tp_src), only
destination port (—port-range-min, —port-range-max).

To solve the lack of source port information, I propose the following
addition to the security groups extension API to allow a match on source port:
—source-port-range-min, —source-port-range-max. Specifically, this would enable
a stateless firewall implementation for UDP and ICMP security group rules.


3. OVSFirewallDriver implementation

Current neutron.agent.firewall.FirewallDriver implementations are based off of
iptables (neutron/agent/linux/iptables_firewall.py: IptablesFirewallDriver,
OVSHybridIptablesFirewallDriver). This blueprint describes implementing a
FirewallDriver sub-class with Open vSwitch flow programming.

* drop all packets by default
* prevent IP spoofing based on port's mac address (compatible with
  allowed_address_pairs extension)
* handles ARP, DHCP, ICMPv6 RA
* convert security group rules to OVS flows (IPv4, IPv6, TCP, UDP, ICMP,
  ICMPv6)
* single TCP/UDP port per OVS flow


4. Connection-tracking security group rules validation

At the neutron-server level, we'll add a configuration flag,
enable_connection_tracking, to validate the difference between security group
rules that require a connection tracking firewall versus those that do not.
Based on the flag we will reject the user's input if the speficied security
group rule requires connection tracking and the flag is disabled.


Alternatives
------------

1. ovs_neutron_agent related changes

None.


2. Extension of security groups extension

In Open vSwitch today, there are two best practice options of implementing
firewalls[1]:

* reflexive learn actions
* stateless ACLs with tcp_flags=ack (available in OVS v2.1.0+)

In the same e-mail thread[2], the tradeoffs between the two choices were
discussed:

* reflexive learning is not as performant as it cuts into how many flows a
  megaflow can wildcard, e.g. the less that can be wildcarded, the more OVS
  will have to hit userspace for flows

* "Using the learn action is strictly more correct, since it's only allowing
  return traffic that's in response to traffic that was previously seen. TCP
  flag matching allows reasonable megaflows, but just blocking on the SYN flags
  isn't as secure, since an attacker can get traffic through--they just can't
  initiate a new connection."

The preferred implementation is 'stateless ACLs with tcp_flags=ack' to emulate
stateful behavior (at least in TCP) because reflexive learning is not as performant.


3. OVSFirewallDriver implementation

None.


4. Connection-tracking security group rules validation

None.


Data model impact
-----------------
setattr(sgdb.SecurityGroupRule, 'source_port_range_min', sa.Column(sa.Integer))
setattr(sgdb.SecurityGroupRule, 'source_port_range_max', sa.Column(sa.Integer))

A corresponding migration will be enabled for the ML2 driver.


REST API impact
---------------
source-port-range-min and source-port-range-max will follow exactly to their
port-range-min and port-range-max counterparts. Looking at
APIChangeGuidelines[3], this change would fall under "Adding an optional
property to a resource representation which may be supplied by clients,
assuming the API previously would ignore this property".

Security group rule validation will raise a new type of exception when invalid
input is provided based on enable_connection_tracking flag.


Security impact
---------------
Loss of stateful firewall functionality.
Security group rules can now be programmed through the API as OVS flows.


Notifications impact
--------------------
None.

The iptables firewall already supports the RPC API in this capacity and unit
tests around source port can be added to
neutron/tests/unit/test_iptables_firewall.py.


Other end user impact
---------------------
source-port-range-min and source-port-range-max will follow exactly to their
port-range-min and port-range-max counterparts in python-neutronclient.


Performance Impact
------------------
OVS flows programming in the OVSFirewallDriver should be comparable to
performance of iptables programming. In terms of number of flows in the
datapath, this number needs to be tested and benchmarked once the
implementation is available. We'd expect the OVSFirewallDriver to be more
performant than the OVSHybridIptablesFirewallDriver due to the lack of an
extra bridge.

Measurements to include: number of concurrent connections, overall bandwidth
compared to line rate, latency.


Other deployer impact
---------------------
* A new firewall_driver option will be available, OVSFirewallDriver.
* a new flag to enable connection tracking security group rule validation,
  enable_connection_tracking.


Developer impact
----------------
Flows programming in ovs_neutron_agent will be advanced to allow for cookies.


Implementation
==============

Assignee(s)
-----------

Primary assignee:
  Amir Sadoughi <amir-sadoughi>

Other contributors:
  TBD


Work Items
----------
* Previous work completed (waiting for review) in Icehouse cycle
* OVSFirewallDriver implementation
* Connection tracking flag and security group rule validation
* Tool to explain security group rule flows to operators inexperienced with OVS


Dependencies
============
* neutron-ml2-mechanismdriver-extensions implementation to allow for security
  groups API extension on OVS MechanismDriver
* OVS v1.5.0+ for cookie
* OVS v2.1.0+ for tcp_flags


Testing
=======
* tempest tests TBD
* TBD: OVS version available in the gate


Documentation Impact
====================
* source-port-range-min, source-port-range-max as part of new extension
* a new firewall_driver option
* enable_connection_tracking flag and corresponding significance for security
  group API behavior


References
==========
[1] http://openvswitch.org/pipermail/discuss/2013-December/012425.html
[2] http://openvswitch.org/pipermail/discuss/2013-December/012433.html
[3] http://paste.openstack.org/show/55103/
[4] https://wiki.openstack.org/wiki/APIChangeGuidelines
[5] http://openvswitch.org/pipermail/dev/2014-May/040567.html
