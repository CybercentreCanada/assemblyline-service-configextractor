ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch AS base

ENV SERVICE_PATH configextractor_.ConfigExtractor
ENV YARA_VERSION=4.2.0
USER root
RUN apt-get update && apt-get install -y git libssl1.1 libmagic1 && rm -rf /var/lib/apt/lists/*
# Create a temporary image to do our compiling in
FROM base AS build

RUN apt-get update && apt-get install -y git libssl-dev libmagic-dev automake libtool make gcc wget libjansson-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Compile and install YARA
RUN wget -O /tmp/yara.tar.gz https://github.com/VirusTotal/yara/archive/v$YARA_VERSION.tar.gz
RUN tar -zxf /tmp/yara.tar.gz -C /tmp
WORKDIR /tmp/yara-$YARA_VERSION
RUN ./bootstrap.sh
RUN ./configure --enable-cuckoo --enable-magic --enable-dotnet --with-crypto --prefix /tmp/yara_install
RUN make
RUN make install

# Build the yara python plugins, install other dependencies
USER assemblyline
RUN touch /tmp/before-pip
# Get ConfigExtractor library
RUN git clone --recurse-submodules https://github.com/CybercentreCanada/configextractor-py.git /tmp/configextractor-py
RUN pip install --global-option="build" --global-option="--enable-dotnet" --global-option="--enable-magic" yara-python==$YARA_VERSION
RUN pip install --no-cache-dir --user --use-deprecated=legacy-resolver \
 gitpython plyara /tmp/configextractor-py/RATDecoders/ /tmp/configextractor-py/ && rm -rf ~/.cache/pip

RUN git clone https://github.com/kevoreilly/CAPEv2.git /tmp/CAPEv2

# Remove disabled/test parsers
RUN rm -f /tmp/CAPEv2/modules/processing/parsers/CAPE/*.py_disabled
RUN rm -f /tmp/CAPEv2/modules/processing/parsers/CAPE/test_cape.py

# Remove 'bad' parsers
RUN rm -f /tmp/CAPEv2/modules/processing/parsers/CAPE/LokiBot.py
RUN rm -f /tmp/CAPEv2/modules/processing/parsers/CAPE/GuLoader.py

RUN mkdir -p /tmp/al_service/CAPEv2/modules/processing/parsers/CAPE/
RUN cp -r /tmp/CAPEv2/modules/processing/parsers/CAPE/* /tmp/al_service/CAPEv2/modules/processing/parsers/CAPE/
RUN mkdir -p /tmp/al_service/CAPEv2/lib
RUN cp -r /tmp/CAPEv2/lib/* /tmp/al_service/CAPEv2/lib/

RUN rm -rf /tmp/CAPEv2

# # Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# # files that already exist in the base image
# RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# # Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
# USER root
# RUN chown root:root -R /var/lib/assemblyline/.local

# Revert back to before the compile
FROM base

COPY --from=build /tmp/yara_install /usr/local
COPY --from=build /tmp/configextractor-py/dependencies /opt/al_service/dependencies
COPY --from=build /tmp/al_service/CAPEv2/ /opt/al_service/CAPEv2
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Create directories
RUN mkdir -p /mount/updates
RUN mkdir -p /opt/al_service

# Copy service code
WORKDIR /opt/al_service
COPY . .

# Make sure we actually have the right version of pyparsing by uninstalling it as root
# then later reinstalling an exact version as the user account
RUN pip uninstall --yes pyparsing flask

# Cleanup
RUN rm ./Dockerfile

# Set owner
RUN chown -R assemblyline /opt/al_service

# Patch version in manifest
ARG version=4.0.0.dev1
ENV PUBLIC_SERVICE_VERSION=$version
ENV CAPE_PARSERS_DIR=/opt/al_service/CAPEv2/modules/processing/parsers/CAPE/
ENV PYTHONPATH=$PYTHONPATH:/opt/al_service/CAPEv2/
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
RUN pip install --user pyparsing==2.3.0 flask~=1.1.0
