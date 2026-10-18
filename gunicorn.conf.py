"""Production server settings.

ONE worker on purpose: the rate limiter, cache, health counters and daily budget live in memory,
so several worker processes would each get their own copy and break VirusTotal pacing.
Threads give the concurrency instead.
"""
import os

bind = f"0.0.0.0:{os.getenv('PORT', '8000')}"
workers = 1
worker_class = "gthread"
threads = int(os.getenv("THREADS", "16"))
timeout = 180            # a lookup can wait up to 2 minutes in the VirusTotal queue
graceful_timeout = 30
keepalive = 5
accesslog = None         # the app writes its own audit log
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info")
