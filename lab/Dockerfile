FROM python:3.12-slim

# curl = the exfil callback tool; iputils-ping = the modeled connectivity tool.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl iputils-ping && rm -rf /var/lib/apt/lists/*

WORKDIR /lab
COPY . /lab

# All services run inside the container; the runner spawns target + listener
# and executes the exploits. Isolation is the point — command-injection
# payloads never touch the host.
CMD ["python3", "run_lab.py"]
