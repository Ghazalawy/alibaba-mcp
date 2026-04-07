FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data logs

EXPOSE 8766
CMD ["python", "alibaba_mcp_server.py", "--proxy-headers"]
