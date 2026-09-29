FROM python:2.7-slim
# Deliberately pinned to Python 2.7 (EOL 2020-01-01, permanently past
# end-of-life). Used only to give Xeol (Layer 9 — EOL Detection) a
# deterministic, always-true finding when the image built from this
# Dockerfile is scanned in `docker:` mode; unlike a directory/filesystem
# scan, Xeol's binary cataloger only matches real installed runtimes inside
# an actual container image, not text in a Dockerfile FROM line. requests
# 2.6.0 / pyyaml 5.3.1 (see requirements.txt) both still install cleanly
# under Python 2.7.

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Explicitly runs as root
USER root

EXPOSE 8080

CMD ["python", "app.py"]
