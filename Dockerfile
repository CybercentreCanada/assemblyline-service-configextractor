ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH=configextractor_.configextractor_.ConfigExtractor

# Combine apt operations and cleanup in single layer
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdnlib2.1-cil \
    g++ \
    dirmngr \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install mono in single layer with cleanup
RUN gpg --homedir /tmp --no-default-keyring \
    --keyring /usr/share/keyrings/mono-official-archive-keyring.gpg \
    --keyserver hkp://keyserver.ubuntu.com:80 \
    --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF \
    && echo "deb [signed-by=/usr/share/keyrings/mono-official-archive-keyring.gpg] https://download.mono-project.com/repo/debian stable-buster main" \
    | tee /etc/apt/sources.list.d/mono-official-stable.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends mono-complete \
    && rm -rf /var/lib/apt/lists/* /tmp/.gnupg*

# Switch to assemblyline user for pip operations
USER assemblyline

# Uninstall yara-python and install uv + configextractor in one layer
RUN pip uninstall -y yara-python

# Switch back to root for directory/file operations
USER root
RUN pip install --no-cache-dir uv \
    && uv pip install --system --no-cache git+https://github.com/CybercentreCanada/configextractor-py.git

# Create directories in single command
RUN mkdir -p /mount/updates /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY --chown=assemblyline:assemblyline . .

# Patch version in manifest
ARG version=4.0.0.dev1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user for runtime
USER assemblyline
