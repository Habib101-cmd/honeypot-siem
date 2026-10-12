FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY rules.py alert.py ./
USER nobody
CMD ["python", "-u", "alert.py"]
