{%- from "iptables/map.jinja" import iptables with context %}

# reset policies
include:
  - iptables.install 

{%- if iptables.enabled %}
  {%- set tables   = iptables.get('tables', {}) %}

  {%- if iptables.reset %}

{%- for chain in ['INPUT', 'FORWARD', 'OUTPUT'] %}
  {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_reset_policy_filter_{{ chain }}_{{ ipfamily }}:
  iptables.set_policy:
    - table: filter
    - chain: {{ chain }}
    - policy: ACCEPT
    - family: {{ ipfamily }}
    - require:
      - sls: iptables.install
  {%- endfor %}
{%- endfor %}

{%- for chain in ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'] %}
  {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_reset_policy_mangle_{{ chain }}_{{ ipfamily }}:
  iptables.set_policy:
    - table: mangle
    - chain: {{ chain }}
    - policy: ACCEPT
    - family: {{ ipfamily }}
    - require:
      - sls: iptables.install
  {%- endfor %}
{%- endfor %}

{%- for chain in ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'] %}
  {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_reset_policy_nat_{{ chain }}_{{ ipfamily }}:
  iptables.set_policy:
    - table: nat
    - chain: {{ chain }}
    - policy: ACCEPT
    - family: {{ ipfamily }}
    - require:
      - sls: iptables.install
  {%- endfor %}
{%- endfor %}

# Flush
{%- for table in ['filter', 'mangle', 'nat'] %}
  {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_flush_{{ table }}_{{ ipfamily }}:
  iptables.flush:
    - table: {{ table }}
    - family: {{ ipfamily }}
    - require:
      - iptables: iptables_reset_policy_*
  {%- endfor %}
{%- endfor %}

# accept all traffic on loopback
{%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_allow_localhost_{{ ipfamily }}:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - in-interface: lo
    - save: True
    - family: {{ ipfamily }}
    - require:
      - iptables: iptables_flush_*
{%- endfor %}

# Allow related/established sessions
{%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_allow_established_{{ ipfamily }}:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    - match: state
    - connstate: 'RELATED,ESTABLISHED'
    - save: True      
    - family: {{ ipfamily }}
    - require:
      - iptables: iptables_allow_localhost_*
{%- endfor %}      

{%- endif %}

# Generate rules for whitelisting IP classes
{%- for ip in iptables.get('whitelist', {}) %}
iptables_allow_{{ip}}:
  iptables.append:
     - table: filter
     - chain: INPUT
     - jump: ACCEPT
     - source: {{ ip }}
     - save: True
{%- endfor %}



{%- for table, table_params in tables.items() %}
  {%- set chains = table_params.get('chains', {}) %}
  {%- for chain, chain_params in chains.items() %}
    {%- set policy = chain_params.get('policy', 'ACCEPT')|upper %}
    {%- set rules  = chain_params.get('rules', {}) %}
    {%- for rule, params in rules.items() %}
      {%- set jump = params.get('jump', 'ACCEPT')|upper %}
iptables_rule_{{table}}_{{chain}}_{{rule}}_{{jump}}:
  iptables.append:
    - table: {{table|lower}}
    - chain: {{chain|upper}}
    - jump: {{jump|upper}}
    {%- if params.position is defined %}
    - position: {{ params.position }}
    {%- endif %}
    {%- if params.comment is defined %}
    - comment: {{ params.comment }}
    {%- endif %}
    {%- if params.source is defined %}
    - source: {{ params.source }}
    {%- endif %}
    {%- if params.destination is defined %}
    - destination: {{ params.destination }}
    {%- endif %}
    {%- if params.ports is defined %}
    - dports: {{ params.ports|default(service) }}
    {%- endif %}
    - proto: {{ params.proto|default('tcp') }}
    {%- if params.in_interface is defined %}
    - in-interface: {{ params.in_interface }}
    {%- endif %}
    {%- if params.out_interface is defined %}
    - out-interface: {{ params.out_interface }}
    {%- endif %}
    {%- if params.match is defined %}
    - match: {{ params.match }}
    {%- endif %}
    {%- if params.connstate is defined %}
    - connstate: {{ params.connstate|join(',') }}
    {%- endif %}
    - save: True
    - require_in:
      - iptables: iptables_policy_{{table}}_{{chain}}_ipv4
      - iptables: iptables_policy_{{table}}_{{chain}}_ipv6
    {%- endfor %}

    {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_policy_{{table}}_{{chain}}_{{ ipfamily }}:
  iptables.set_policy:
    - table: {{table|lower}}
    - chain: {{chain|upper}}
    - policy: {{policy|upper}}
    - family: {{ ipfamily }}
    - save: True
    {%- endfor %}

  {%- endfor %}
{%- endfor %}
{%- endif %}

