{% from "iptables/map.jinja" import iptables with context %}

# Install required packages for firewalling      
iptables_packages:
  pkg.installed:
    - pkgs:
      {%- for pkg in iptables.packages %}
      - {{pkg}}
      {%- endfor %}
