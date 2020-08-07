FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH configextractor.ConfigExtractor

USER root
RUN apt-get update && apt-get install -y git libssl1.1 libmagic1 && rm -rf /var/lib/apt/lists/*
# Create a temporary image to do our compiling in
FROM base AS build

RUN apt-get update && apt-get install -y git libssl-dev build-essential libmagic-dev automake libtool make gcc wget  && rm -rf /var/lib/apt/lists/*

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v3.11.0.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-3.11.0
RUN ./bootstrap.sh
RUN ./configure --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
RUN make
RUN make install

# Build the yara python plugins
USER assemblyline
RUN touch /tmp/before-pip
RUN pip install --no-cache-dir --user yara-python gitpython plyara && rm -rf ~/.cache/pip

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Revert back to before the compile
FROM base

COPY --from=build /tmp/yara_install /usr/local
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Install MWCP and packages
RUN pip uninstall --yes pyparsing
RUN pip install -r requirements.txt

# Cleanup
RUN rm ./Dockerfile

# Set owner
RUN chown -R assemblyline /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml


# Switch to assemblyline user
USER assemblyline

RUN pip install --user pyparsing==2.3.0


