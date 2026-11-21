# The scorer builds this on linux/amd64 and runs it with no network. The
# digest is the image we labeled every commit in: its Python and SQLite
# decide which sqlglot tests run, so keep it if your image runs them.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 SKIP_INTEGRATION=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore \
    BLAST_RADIUS_TPC_MEMO=0 BLAST_RADIUS_TPC_PLAN=1
COPY requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir -r /app/requirements.lock
# Default-off prospective research needs the exact public source and fixtures.
RUN python -c "import hashlib,io,os,tarfile,urllib.request; \
sha='eb11aec4be8cb2122afe713a4816662c3f0fb2fa'; \
d=urllib.request.urlopen('https://github.com/tobymao/sqlglot/archive/%s.tar.gz'%sha,timeout=120).read(); \
assert hashlib.sha256(d).hexdigest()=='93b2445f15f395b81c20556777ece19a6c7507df950f13fa9fac4a3be739af0d'; \
tarfile.open(fileobj=io.BytesIO(d)).extractall('/app',filter='data'); \
os.rename('/app/sqlglot-'+sha,'/app/sqlglot-pinned')" \
 && python -m compileall -q --invalidation-mode checked-hash /app/sqlglot-pinned/sqlglot /app/sqlglot-pinned/tests
RUN mkdir -p /opt && ln -s /app/sqlglot-pinned /opt/sqlglot
COPY selector.py /app/selector.py
COPY registry_key_research.py /app/registry_key_research.py
COPY registry_key_research_model.json.gz /app/registry_key_research_model.json.gz
COPY query_modifier_research.py /app/query_modifier_research.py
COPY query_modifier_model.json.gz /app/query_modifier_model.json.gz
COPY tokenizer_setting_branch.py /app/tokenizer_setting_branch.py
COPY tokenizer_setting_branch_model.json.gz /app/tokenizer_setting_branch_model.json.gz
COPY tpc_fixture_verify.py /app/tpc_fixture_verify.py
COPY tpc_fixture_verify_child.py /app/tpc_fixture_verify_child.py
COPY broad_verify_manifest.json.gz /app/broad_verify_manifest.json.gz
COPY vendor/sqlglot-eb11aec.tar.xz /app/sqlglot-eb11aec.tar.xz
COPY binary_copy_patch.py /app/binary_copy_patch.py
COPY tpc_entry_key_access.py /app/tpc_entry_key_access.py
COPY semantic.py /app/semantic.py
COPY shared_arg_write_runtime.py /app/shared_arg_write_runtime.py
COPY none_static_runtime.py /app/none_static_runtime.py
COPY tpc_rule_replay.py /app/tpc_rule_replay.py
COPY tpc_rule_fast.py /app/tpc_rule_fast.py
COPY tpc_rule_fast_runtime.py /app/tpc_rule_fast_runtime.py
COPY selector_model.json.gz /app/selector_model.json.gz
COPY semantic_sources.json.gz /app/semantic_sources.json.gz
COPY zero_reader_model.json.gz /app/zero_reader_model.json.gz
COPY predicate_profile.json.gz /app/predicate_profile.json.gz
COPY arg_type_derivation_model.json.gz /app/arg_type_derivation_model.json.gz
COPY class_attribute_model.json.gz /app/class_attribute_model.json.gz
COPY module_constant_model.json.gz /app/module_constant_model.json.gz
COPY fresh_alias_profile.json.gz /app/fresh_alias_profile.json.gz
COPY import_line_profile.json.gz /app/import_line_profile.json.gz
COPY shared_arg_write_model.json.gz /app/shared_arg_write_model.json.gz
COPY none_static_profile.json.gz /app/none_static_profile.json.gz
COPY fixture_binary_preimages.json.gz /app/fixture_binary_preimages.json.gz
COPY tpc_entry_reader_provenance.json.gz /app/tpc_entry_reader_provenance.json.gz
COPY new_module_model.json.gz /app/new_module_model.json.gz
COPY tools/executor_result_memo.py /app/executor_result_memo.py
COPY tools/build_executor_result_memo.py /app/build_executor_result_memo.py
COPY tools/executor_result_memo.json.gz /app/executor_result_memo.json.gz
COPY tools/verify_prospective_executor_memo.py /app/verify_prospective_executor_memo.py
COPY tools/run_prospective_executor_memo.py /app/run_prospective_executor_memo.py
COPY tpc_plan_runtime.py /app/tpc_plan_runtime.py
COPY tpc_graph_digest.py /app/tpc_graph_digest.py
COPY tpc_plan_profile.json.gz /app/tpc_plan_profile.json.gz
CMD ["python", "/app/selector.py"]
