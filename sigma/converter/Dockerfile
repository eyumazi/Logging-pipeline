FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir pyyaml
COPY convert.py /app/convert.py
CMD ["python", "/app/convert.py"]