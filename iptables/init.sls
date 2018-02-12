{% from "iptables/map.jinja" import iptables as iptables_map with context %}

include:
  - iptables.install
  {%- if salt['pillar.get']('iptables:enabled', True) %}
  - iptables.config
  {%- endif %}
