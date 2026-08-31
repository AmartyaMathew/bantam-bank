FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MIGRATIONS_DIR=/app/migrations

RUN groupadd --system --gid 10001 bantam \
    && useradd --system --uid 10001 --gid bantam --home-dir /app bantam

WORKDIR /app
COPY pyproject.toml README.md ./
COPY bantam ./bantam
COPY security ./security
RUN python -m pip install --no-cache-dir .
COPY migrations ./migrations
RUN chmod -R a+rX /app

USER 10001
EXPOSE 8080
ENTRYPOINT ["python", "-m", "bantam"]
CMD ["api"]
