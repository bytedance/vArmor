#!/bin/sh
# source venv/bin/activate

gunicorn -b :5000 -w 2 wsgi:app
