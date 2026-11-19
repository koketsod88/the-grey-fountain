FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY . /app
RUN pip install --no-cache-dir \
      fastapi==0.165.0 \
      uvicorn==0.54.0 \
      httpx==0.28.1 \
      pydantic==2.14.3 \
      PyYAML==6.0.3 \
      opentelemetry-api==1.45.2

EXPOSE 8088
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088"]
