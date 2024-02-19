ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH configextractor_.configextractor_.ConfigExtractor
ENV YARA_VERSION=4.3.1

USER assemblyline
RUN pip uninstall -y yara-python

USER root
RUN apt-get update && apt-get install -y git libssl-dev libmagic1 mono-complete gcc libdnlib2.1-cil && rm -rf /var/lib/apt/lists/*
# Create a temporary image to do our compiling in
FROM base AS build

RUN apt-get update && apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc wget libjansson-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-${YARA_VERSION}
RUN ./bootstrap.sh
RUN ./configure --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
RUN make
RUN make install


# Build the yara python plugins, install other dependencies
USER assemblyline
RUN touch /tmp/before-pip

# Get ConfigExtractor library
RUN pip install -U git+https://github.com/CybercentreCanada/configextractor-py.git

RUN pip install --no-cache-dir --user --global-option="build" --global-option="--enable-magic" yara-python==${YARA_VERSION}
RUN pip install --no-cache-dir --user gitpython plyara markupsafe==2.0.1

# Public libraries that can be used by parsers
RUN pip install --no-cache-dir --user netstruct beautifulsoup4 pyOpenSSL

# Remove uses of pycrypto
RUN pip uninstall -y -q pycrypto

# Revert back to before the compile
FROM base

RUN apt-get update && apt-get install -y libssl-dev libmagic-dev automake libtool make gcc libjansson-dev pkg-config && rm -rf /var/lib/apt/lists/*

COPY --from=build /tmp/yara_install /usr/local
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Cleanup
RUN rm ./Dockerfile

# Set owner
RUN chown -R assemblyline /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
