"""
Well-defined parameter names.

The names will be used as parameter names to store the actual value
in the database.
"""

# Store_id of the selected certificate store
CERT_STORE = '944f54e6-1226-4910-a04a-9ecfe64e1a8b'

# Serial of the certificate to use to sign new certificates
CERT_KEYSIGN = 'c96a8d20-9746-4a95-8d91-17c762b78cf5'
# Serial of the certificate to use to sign new CRLs
CERT_CRLSIGN = 'c3da02d3-3abf-467a-9f6d-666256eb606f'

# Serial of a dummy certificate used to generate CSRs
# Needed for the certificate creation process
CERT_CSRSIGN = '2ea16b24-3350-44ea-a1ba-7d546d4941b4'