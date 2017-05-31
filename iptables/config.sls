{%- if salt['pillar.get']('iptables:enabled') %}
  {%- set iptables = salt['pillar.get']('iptables', {}) %}
  {%- set tables   = iptables.get('tables', {}) %}

# reset policies
include:
  - iptables.install 

{%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_reset_policy_{{ ipfamily }}:
  iptables.set_policy:
    - table: filter
    - chain: INPUT
    - policy: ACCEPT
    - family: {{ ipfamily }}
    - require:
      - sls: iptables.install
{%- endfor %}

# Flush
{%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_flush_{{ ipfamily }}:
  iptables.flush:
    - table: filter
    - family: {{ ipfamily }}
    - require:
      - iptables: iptables_reset_policy_*
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
    - require:
      - iptables: iptables_allow_established_*
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
    - require:
      - iptables: iptables_reset_policy_*
    {%- endfor %}

  {%- endfor %}
{%- endfor %}
{%- endif %}

