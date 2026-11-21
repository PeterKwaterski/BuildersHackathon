# The scorer builds this on linux/amd64 and runs it with no network. The
# digest is the image we labeled every commit in: its Python and SQLite
# decide which sqlglot tests run, so keep it if your image runs them.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
COPY vendor/sqlglot-eb11aec.tar.xz /app/sqlglot-eb11aec.tar.xz
RUN python -c "import tarfile; tarfile.open('/app/sqlglot-eb11aec.tar.xz').extractall('/opt', filter='data')" \
    && rm /app/sqlglot-eb11aec.tar.xz \
    && python -m compileall -q --invalidation-mode checked-hash /opt/sqlglot/sqlglot /opt/sqlglot/tests
COPY selector.py /app/selector.py
COPY semantic.py /app/semantic.py
COPY semantic_noops.py /app/semantic_noops.py
COPY runtime_verify.py /app/runtime_verify.py
COPY max_nodes_exact.py /app/max_nodes_exact.py
COPY selector_model.json.gz /app/selector_model.json.gz
COPY semantic_sources.json.gz /app/semantic_sources.json.gz
COPY zero_reader_model.json.gz /app/zero_reader_model.json.gz
COPY predicate_profile.json.gz /app/predicate_profile.json.gz
COPY arg_type_derivation_model.json.gz /app/arg_type_derivation_model.json.gz
COPY class_attribute_model.json.gz /app/class_attribute_model.json.gz
COPY tokenizer_setting_flow_model.json.gz /app/tokenizer_setting_flow_model.json.gz
COPY module_constant_model.json.gz /app/module_constant_model.json.gz
COPY code_reflection_model.json.gz /app/code_reflection_model.json.gz
COPY fresh_alias_profile.json.gz /app/fresh_alias_profile.json.gz
COPY generator_dispatch_model.json.gz /app/generator_dispatch_model.json.gz
COPY new_module_model.json.gz /app/new_module_model.json.gz
COPY function_default_model.json.gz /app/function_default_model.json.gz
COPY max_nodes_exact_profile.json.gz /app/max_nodes_exact_profile.json.gz
CMD ["python", "/app/selector.py"]
