FROM python:3-slim

WORKDIR /

# Update the image to remediate any vulnerabilities.
RUN apt update && apt -y upgrade && apt -y dist-upgrade && rm -rf /var/lib/apt/lists/*

# Remove suid & sgid bits from all files.
RUN find / -xdev -perm /6000 -exec chmod ug-s {} \; 2> /dev/null || true

# Copy the ssh-audit code.
COPY ssh-audit.py .
COPY src/ .

# Allow listening on 2222/tcp for client auditing.
EXPOSE 2222

# Drop root privileges.
USER nobody:nogroup

ENTRYPOINT ["python3", "/ssh-audit.py"]
