FROM python:3.12-slim

WORKDIR /app

COPY contracts.py .
COPY core/ core/
COPY protocol/ protocol/
COPY attacks/ attacks/
COPY detection/ detection/
COPY app/ app/
COPY pyproject.toml .

RUN pip install --no-cache-dir \
    numpy==2.5.2 \
    pandas==3.0.5 \
    qiskit==2.5.2 \
    qiskit-aer==0.17.2 \
    scipy==1.18.1 \
    streamlit==1.63.0

EXPOSE 8501

CMD ["streamlit", "run", "app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]
