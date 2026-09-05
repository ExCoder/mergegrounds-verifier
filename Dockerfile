FROM python:3.11.16-slim-bookworm@sha256:528257d48c1da0dcecc2e725d1ae34498d60c965f1241e39cd6a85a8859bdf84

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY requirements.lock /app/requirements.lock
RUN python -m pip install --require-hashes --only-binary=:all: -r /app/requirements.lock

COPY --chown=65532:65532 src /app/src

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python", "-m", "mergegrounds_verifier"]
CMD ["--help"]
