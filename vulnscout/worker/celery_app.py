from __future__ import annotations
from celery import Celery
celery_app = Celery("vulnscout", broker="redis://localhost:6379/0")
