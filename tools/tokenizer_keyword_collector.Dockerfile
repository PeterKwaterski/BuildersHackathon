FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git=1:2.47.3-0+deb13u1 \
        openssl=3.5.9-1~deb13u1 \
        ca-certificates=20250419+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY requirements.lock /work/requirements.lock
RUN pip install --no-cache-dir -r /work/requirements.lock

COPY Dockerfile /work/Dockerfile
COPY tools/tokenizer_keyword_collector.Dockerfile /work/tools/tokenizer_keyword_collector.Dockerfile
COPY sample/tests.json /work/sample/tests.json
COPY code_reflection_model.json.gz selector_model.json.gz /work/
COPY tools/collect_dict_access.py /work/tools/collect_dict_access.py
COPY tools/collect_class_attribute_reads.py /work/tools/collect_class_attribute_reads.py
COPY tools/build_tokenizer_setting_flow.py /work/tools/build_tokenizer_setting_flow.py
COPY tools/collect_tokenizer_keyword_values.py /work/tools/collect_tokenizer_keyword_values.py
COPY tools/build_tokenizer_keyword_model.py /work/tools/build_tokenizer_keyword_model.py
COPY tools/finalize_tokenizer_keyword_evidence.py /work/tools/finalize_tokenizer_keyword_evidence.py
COPY tools/sign_tokenizer_keyword_evidence.py /work/tools/sign_tokenizer_keyword_evidence.py
COPY tools/tokenizer_keyword_signature.py /work/tools/tokenizer_keyword_signature.py
COPY tools/tokenizer_keyword_review_public.pem /work/tools/tokenizer_keyword_review_public.pem

ENTRYPOINT ["/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "PYTHONHASHSEED=0", "PYTHONSAFEPATH=1", "PYTHONPATH=/work/tools", "PYTHONDONTWRITEBYTECODE=1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1", "/usr/local/bin/python"]
