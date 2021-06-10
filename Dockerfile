FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH configextractor.ConfigExtractor

USER root
RUN apt-get update && apt-get install -y git libssl1.1 libmagic1 && rm -rf /var/lib/apt/lists/*
# Create a temporary image to do our compiling in
FROM base AS build

RUN apt-get update && apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc wget libjansson-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v4.1.0.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-4.1.0
RUN ./bootstrap.sh
RUN ./configure --enable-cuckoo --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
RUN make
RUN make install

# Get MWCFG modules
WORKDIR /tmp
RUN git clone https://github.com/c3rb3ru5d3d53c/mwcfg-modules.git modules/

# Build the yara python plugins, install other dependencies
USER assemblyline
RUN touch /tmp/before-pip
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user magic-yara-python gitpython plyara -r requirements.txt && rm -rf ~/.cache/pip

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
USER root
RUN chown root:root -R /var/lib/assemblyline/.local

# Revert back to before the compile
FROM base

COPY --from=build /tmp/yara_install /usr/local
COPY --from=build /tmp/modules /opt/al_service
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Make sure we actually have the right version of pyparsing by uninstalling it as root
# then later reinstalling an exact version as the user account
RUN pip uninstall --yes pyparsing

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


