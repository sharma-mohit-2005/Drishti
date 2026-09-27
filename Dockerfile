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
VOLUME ["/data", "/scan"]
EXPOSE 8765
CMD ["qscan", "serve", "--host", "0.0.0.0", "--port", "8765"]
