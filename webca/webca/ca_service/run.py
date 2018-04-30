"""Import this module to run the service"""

import django
django.setup()

#pylint: disable=c0413
from webca.ca_service.service import CAService
CAService().run()
