# Default duration of a certificate in seconds (5 years)
CERT_DURATION = 60*60*24*365*5

# KeyUsage enumeration

KU_DIGITALSIGNATURE = 1
KU_NONREPUDIATION   = 2
KU_KEYENCIPHERMENT  = 3
KU_DATAENCIPHERMENT = 4
KU_KEYAGREEMENT     = 5
KU_KEYCERTSIGN      = 6
KU_CRLSIGN          = 7
KU_ENCIPHERONLY     = 8
KU_DECIPHERONLY     = 9

KEY_USAGE = {
    KU_DIGITALSIGNATURE : 'digitalSignature',
    KU_NONREPUDIATION   : 'nonRepudiation',
    KU_KEYENCIPHERMENT  : 'keyEncipherment',
    KU_DATAENCIPHERMENT : 'dataEncipherment',
    KU_KEYAGREEMENT     : 'keyAgreement',
    KU_KEYCERTSIGN      : 'keyCertSign',
    KU_CRLSIGN          : 'cRLSign',
    KU_ENCIPHERONLY     : 'encipherOnly',
    KU_DECIPHERONLY     : 'decipherOnly'
}

# ExtendedKeyUsage enumeration

EKU_SERVERAUTH      = 1
EKU_CLIENTAUTH      = 2
EKU_CODESIGNING     = 3
EKU_EMAILPROTECTION = 4
EKU_TIMESTAMPING    = 5
EKU_OCSPSIGNING     = 6
EKU_IPSECIKE        = 7
EKU_MSCODEIND       = 8
EKU_MSCODECOM       = 9
EKU_MSCTLSIGN       = 10
EKU_MSEFS           = 11

EXT_KEY_USAGE = {
    EKU_SERVERAUTH      : 'serverAuth',
    EKU_CLIENTAUTH      : 'clientAuth',
    EKU_CODESIGNING     : 'codeSigning',
    EKU_EMAILPROTECTION : 'emailProtection',
    EKU_TIMESTAMPING    : 'timeStamping',
    EKU_OCSPSIGNING     : 'OCSPSigning',
    EKU_IPSECIKE        : 'ipsecIKE',
    EKU_MSCODEIND       : 'msCodeInd',
    EKU_MSCODECOM       : 'msCodeCom',
    EKU_MSCTLSIGN       : 'msCTLSign',
    EKU_MSEFS           : 'msEFS'
}
