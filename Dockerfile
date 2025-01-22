ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH configextractor_.configextractor_.ConfigExtractor

USER assemblyline
RUN pip uninstall -y yara-python

USER root
RUN apt-get update && apt-get install -y libdnlib2.1-cil g++ dirmngr ca-certificates gnupg
RUN pip install uv
# Install latest version of mono (https://www.mono-project.com/download/stable/#download-lin-debian)
RUN gpg --homedir /tmp --no-default-keyring --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
RUN echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main"  | tee /etc/apt/sources.list.d/mono-official-stable.list
RUN apt update && apt install -y mono-complete && rm -rf /var/lib/apt/lists/*

# Install configextractor-py
RUN uv pip install --system git+https://github.com/CybercentreCanada/configextractor-py.git

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Set owner
RUN chown -R assemblyline /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
