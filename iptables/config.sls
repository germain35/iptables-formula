{%- if salt['pillar.get']('iptables:enabled') %}
  {% set iptables    = salt['pillar.get']('iptables', {}) %}
  {% set services    = iptables.get('services', {}) %}
  {% set strict_mode = iptables.get('strict', false) %}

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
iptables{{ip}}_allow:
  iptables.append:
     - table: filter
     - chain: INPUT
     - jump: ACCEPT
     - source: {{ ip }}
     - save: True
{%- endfor %}

{%- for service, params in services.items() %}
iptables_{{service}}_allow:
  iptables.append:
    - table: filter
    - chain: INPUT
    - jump: ACCEPT
    {%- if params.position is defined %}
    - position: {{ params.position }}
    {%- endif %}
    {%- if params.comment is defined %}
    - comment: {{ params.comment }}
    {%- endif %}
    {%- if params.source is defined %}
    - source: {{ params.source }}
    {%- endif %}
    {%- if params.ports is defined %}
    - dports: {{ params.ports|default(service) }}
    {%- endif %}
    - proto: {{ params.proto|default('tcp') }}
    {%- if params.interface is defined %}
    - in-interface: {{ params.interface }}
    {%- endif %}
    - save: True
    - require:
      - iptables: iptables_allow_established_*
{%- endfor %}


{%- if strict_mode %}
# Set the policy to deny everything unless defined
  {%- for ipfamily in ['ipv4', 'ipv6'] %}
iptables_enable_reject_policy_{{ ipfamily }}:
  iptables.set_policy:
    - table: filter
    - chain: INPUT
    - policy: DROP
    - family: {{ ipfamily }}
    - require:
      - iptables: iptables_reset_policy_*
      - iptables: iptables_*_allow
  {%- endfor %}
{%- endif %}

{%- endif %}
