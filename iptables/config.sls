# reset policies
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
