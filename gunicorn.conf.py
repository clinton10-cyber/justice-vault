import multiprocessing

bind = "0.0.0.0:10000"
workers = 4
threads = 4
worker_class = "gthread"
timeout = 120
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
graceful_timeout = 30
