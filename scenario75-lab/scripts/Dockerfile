# One-shot log injector: runs generate_logs.py then exits.
FROM python:3.12-alpine

WORKDIR /opt/scripts
COPY generate_logs.py ./

CMD ["python3", "generate_logs.py"]
