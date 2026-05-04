FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV APP_ENV=production
ENV PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/lib/pkgconfig:/usr/share/pkgconfig

WORKDIR /app

RUN adduser --disabled-password --gecos "" appuser

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
		build-essential \
		gammu \
		libgammu-dev \
		pkg-config \
	&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)"

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "3", "--threads", "4", "--timeout", "120", "main:app"]
