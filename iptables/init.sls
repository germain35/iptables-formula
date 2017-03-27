{% from "iptables/map.jinja" import iptables as iptables_map with context %}

include:
  - iptables.install
  - iptables.config
