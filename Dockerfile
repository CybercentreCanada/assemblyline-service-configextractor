FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH configextractor.ConfigExtractor



# Switch to assemblyline user
USER assemblyline

# Copy ConfigExtractor service code
WORKDIR /opt/al_service
COPY . .

