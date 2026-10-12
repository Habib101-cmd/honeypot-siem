FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests reportlab
COPY report.py .
CMD ["python", "-u", "report.py"]
