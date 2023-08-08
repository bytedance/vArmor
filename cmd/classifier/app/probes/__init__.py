from flask import Blueprint

probes = Blueprint('probes', __name__)

from . import probe
