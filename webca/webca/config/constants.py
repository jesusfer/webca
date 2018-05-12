"""
Well-defined parameter names.

The names will be used as parameter names to store the actual value
in the database.
"""

# Parameter name to identify the serial of the certificate to use to sign new certificates
CERT_KEYSIGN = 'keysign-c96a8d20-9746-4a95-8d91-17c762b78cf5'
# Parameter name to identify the serial of the certificate to use to sign new CRLs
CERT_CRLSIGN = 'crlsign-c3da02d3-3abf-467a-9f6d-666256eb606f'
# Parameter name to identify the serial of the certificate to use to sign user authentication certificates
CERT_USERSIGN = 'usersign-8867be72-25a5-469b-a9a6-78c842389a12'

# Serial of a dummy certificate used to generate CSRs
# Needed for the certificate creation process
CERT_CSRSIGN = 'csrsign-2ea16b24-3350-44ea-a1ba-7d546d4941b4'

# Key to store CRL status and configuration
CRL_CONFIG = 'crlconfig-b953912c-e962-4c0e-b75b-d7faa23c78f2'
