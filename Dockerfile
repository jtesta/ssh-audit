#syntax=docker/dockerfile:1.6.0
FROM scratch AS tmp
# Copy the ssh-audit code.
COPY ssh-audit.py /home/nonroot/
COPY src/ /home/nonroot/

FROM cgr.dev/chainguard/python:latest AS runtime
# Copy files collected in tmp container
COPY --from=tmp --chown=nonroot:nonroot /home/nonroot/ /home/nonroot/
# Allow listening on 2222/tcp for client auditing.
EXPOSE 2222

ENTRYPOINT ["python3", "/home/nonroot/ssh-audit.py"]
