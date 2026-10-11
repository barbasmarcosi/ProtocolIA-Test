# Independent judge, based on frozen ProtocolIA-Test commit 77ec9150...; do not change tools/p4_verify.py.
FROM python:3.12-slim
WORKDIR /app
COPY tools/p4_verify.py /app/tools/p4_verify.py
COPY deployment/p4-render-judge/runner.py /app/runner.py
RUN python -m py_compile tools/p4_verify.py runner.py && sha256sum tools/p4_verify.py
RUN groupadd -g 10002 judge && useradd -u 10002 -g 10002 -M -s /usr/sbin/nologin judge
USER 10002:10002
EXPOSE 10000
CMD ["python","-u","/app/runner.py"]
