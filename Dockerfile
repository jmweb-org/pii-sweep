# Scan a dataset from inside a container by mounting it:
#
#   docker build -t pii-sweep .
#   docker run --rm -v "$PWD:/w" -w /w pii-sweep scan data.parquet --check
#
FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/jmweb-org/pii-sweep"
LABEL org.opencontainers.image.description="Scan dataset files for personally identifiable information."
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

ENTRYPOINT ["pii-sweep"]
CMD ["--help"]
