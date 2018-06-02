"""Import this module to run the service"""
import os
import sys

import django

BASE_DIR = os.path.abspath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    os.path.pardir,
    os.path.pardir,
))
sys.path.append(BASE_DIR)
os.environ["DJANGO_SETTINGS_MODULE"] = "webca.ca_service.settings"

django.setup()

#pylint: disable=c0413
from webca.ca_service.service import CAService

CAService().run()
