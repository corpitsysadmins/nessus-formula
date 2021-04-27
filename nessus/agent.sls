{% from "./defaults/agent.jinja" import agent_data with context -%}

{% if agent_data.use is defined %}

{% if agent_data.use | to_bool %}

nessus_agent_installation:
  pkg.installed:
    - name: {{ agent_data.package_name }}
    - sources:
      - {{ agent_data.package_name }}: {{ agent_data.package_file }}

nessus_agent_linked:
  nessus_agent.linked:
    - nessuscli: {{ agent_data.nessuscli }}
    - host: {{ agent_data.host }}
    - port: {{ agent_data.port }}
    - key: {{ agent_data.key }}
    - status_messages: {{ agent_data.status_messages|json }}
    - require:
      - nessus_agent_installation

nessus_agent_service_running:  
  service.running:
    - name: {{ agent_data.service_name }}
    - enable: True
    - require:
      - nessus_agent_linked

{% else %}

nessus_agent_unlinked:
  nessus_agent.unlinked:
    - nessuscli: {{ agent_data.nessuscli }}
    - status_messages: {{ agent_data.status_messages|json }}

nessus_agent_removal:
  pkg.removed:
    - name: {{ agent_data.package_name }}
    - require:
      - nessus_agent_unlinked

{% endif %}

{% endif %}