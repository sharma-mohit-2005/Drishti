FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY qscan ./qscan
COPY demo ./demo
COPY scripts ./scripts
COPY pyproject.toml README.md ./
ENV QSCAN_DATA=/data
EXPOSE 8765
# Run from /app (not an installed copy in site-packages) so the bundled demo/ folder is found.
# Render, Railway and similar platforms pass the port in $PORT; locally it defaults to 8765.
CMD ["sh", "-c", "python -m qscan serve --host 0.0.0.0 --port ${PORT:-8765}"]
