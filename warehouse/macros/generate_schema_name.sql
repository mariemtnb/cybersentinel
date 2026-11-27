{#- Use the layer name as the schema (staging, intermediate, marts, snapshots) instead of
    dbt's default "<target_schema>_<custom_schema>", so the dashboard queries marts.fct_… -#}
{% macro generate_schema_name(custom_schema_name, node) -%}
    {{ custom_schema_name | trim if custom_schema_name is not none else target.schema }}
{%- endmacro %}
