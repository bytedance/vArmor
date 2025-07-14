#!/bin/sh
# source venv/bin/activate

gunicorn -b :${CLASSIFIER_SERVICE_PORT:-5000} -w 2 wsgi:app
