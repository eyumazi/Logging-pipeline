FROM python:3.11
WORKDIR /app
RUN pip install --no-cache-dir pyyaml
COPY convert.py /app/convert.py
CMD ["python", "/app/convert.py"]