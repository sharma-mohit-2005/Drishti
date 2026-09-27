FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY qscan ./qscan
COPY demo ./demo
COPY scripts ./scripts
COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --no-deps .
ENV QSCAN_DATA=/data
EXPOSE 8765
# Railway and similar platforms pass the port in $PORT; locally it defaults to 8765.
CMD ["sh", "-c", "qscan serve --host 0.0.0.0 --port ${PORT:-8765}"]
