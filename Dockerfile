# The scorer builds this on linux/amd64 and runs it with no network. The
# digest is the image we labeled every commit in: its Python and SQLite
# decide which sqlglot tests run, so keep it if your image runs them.
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
COPY selector.py /app/selector.py
COPY binary_copy_patch.py /app/binary_copy_patch.py
COPY tpc_entry_key_access.py /app/tpc_entry_key_access.py
COPY semantic.py /app/semantic.py
COPY shared_arg_write_runtime.py /app/shared_arg_write_runtime.py
COPY none_static_runtime.py /app/none_static_runtime.py
COPY selector_model.json.gz /app/selector_model.json.gz
COPY semantic_sources.json.gz /app/semantic_sources.json.gz
COPY zero_reader_model.json.gz /app/zero_reader_model.json.gz
COPY predicate_profile.json.gz /app/predicate_profile.json.gz
COPY arg_type_derivation_model.json.gz /app/arg_type_derivation_model.json.gz
COPY class_attribute_model.json.gz /app/class_attribute_model.json.gz
COPY fresh_alias_profile.json.gz /app/fresh_alias_profile.json.gz
COPY shared_arg_write_model.json.gz /app/shared_arg_write_model.json.gz
COPY none_static_profile.json.gz /app/none_static_profile.json.gz
COPY fixture_binary_preimages.json.gz /app/fixture_binary_preimages.json.gz
COPY tpc_entry_reader_provenance.json.gz /app/tpc_entry_reader_provenance.json.gz
CMD ["python", "/app/selector.py"]
