FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests python-dotenv
COPY alert.py .
CMD ["python", "-u", "alert.py"]