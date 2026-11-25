ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE}

RUN pip install --no-cache-dir cryptography==50.0.2 \
    && mkdir -p /var/lib/kgateway-control \
    && chown 10002:10002 /var/lib/kgateway-control
WORKDIR /app
COPY main.py replicas.py state.py sqlite_journal.py usage.py audit.py audit_anchor.py vault.py witness.py batch_reports.py delegation.py budget_window.py registry.py maas_releases.py recovery.py recovery_protocol.py ./
COPY sdk ./sdk
USER 10002:10002
ENTRYPOINT ["python", "/app/main.py"]
