FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
COPY payloads/ payloads/
COPY profiles/ profiles/

RUN pip install --no-cache-dir .

EXPOSE 4171

ENTRYPOINT ["aicu"]
CMD ["--help"]
