FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md requirements.lock LICENSE NOTICE THIRD_PARTY_NOTICES ./
COPY src ./src
COPY fixtures ./fixtures
COPY evaluations ./evaluations
COPY alembic.ini ./
COPY migrations ./migrations

RUN python -m pip install --root-user-action=ignore -r requirements.lock \
    && python -m pip install --root-user-action=ignore --no-deps . \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /nonexistent --shell /usr/sbin/nologin app \
    && mkdir /data \
    && chown 10001:10001 /data

USER 10001:10001

ENTRYPOINT ["python", "-m", "security_triage_agent"]
CMD ["--check"]
