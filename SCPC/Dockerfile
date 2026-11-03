FROM python:3.12-slim
WORKDIR /opt/assurance-lab
COPY src ./src
COPY common.py ./common.py
COPY SCPC ./SCPC
ENV PYTHONPATH=/opt/assurance-lab/src:/opt/assurance-lab
CMD ["python", "SCPC/run_scpc_v2.py"]
