FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY sluice ./sluice
RUN pip install --no-cache-dir .

ENV SLUICE_CONFIG=/etc/sluice/config.yaml
VOLUME ["/etc/sluice", "/var/lib/sluice"]
EXPOSE 4444
ENTRYPOINT ["sluice"]
CMD ["serve", "--config", "/etc/sluice/config.yaml", "--host", "0.0.0.0"]
