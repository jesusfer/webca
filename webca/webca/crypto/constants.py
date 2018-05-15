"""
Constants used in the webca.crypto module.
"""
# Max allowed serial number size is < 20 bits
SERIAL_BYTES = 16

# Default duration of a certificate in seconds (5 years)
CERT_DURATION = 60*60*24*365*5

# Subject components

SUBJECT_DN = [
    'C', 'ST', 'L', 'O', 'OU', 'CN'
]

SUBJECT_PARTS = list(SUBJECT_DN)
SUBJECT_PARTS.append('emailAddress')

# KeyUsage enumeration

KU_DIGITALSIGNATURE = 1
KU_NONREPUDIATION = 2
KU_KEYENCIPHERMENT = 3
KU_DATAENCIPHERMENT = 4
KU_KEYAGREEMENT = 5
KU_KEYCERTSIGN = 6
KU_CRLSIGN = 7
KU_ENCIPHERONLY = 8
KU_DECIPHERONLY = 9

KEY_USAGE = {
    KU_DIGITALSIGNATURE: 'digitalSignature',
    KU_NONREPUDIATION: 'nonRepudiation',
    KU_KEYENCIPHERMENT: 'keyEncipherment',
    KU_DATAENCIPHERMENT: 'dataEncipherment',
    KU_KEYAGREEMENT: 'keyAgreement',
    KU_KEYCERTSIGN: 'keyCertSign',
    KU_CRLSIGN: 'cRLSign',
    KU_ENCIPHERONLY: 'encipherOnly',
    KU_DECIPHERONLY: 'decipherOnly'
}

# ExtendedKeyUsage enumeration

EKU_SERVERAUTH = 1
EKU_CLIENTAUTH = 2
EKU_CODESIGNING = 3
EKU_EMAILPROTECTION = 4
EKU_TIMESTAMPING = 5
EKU_OCSPSIGNING = 6
EKU_IPSECIKE = 7
EKU_MSCODEIND = 8
EKU_MSCODECOM = 9
EKU_MSCTLSIGN = 10
EKU_MSEFS = 11

EXT_KEY_USAGE = {
    EKU_SERVERAUTH: 'serverAuth',
    EKU_CLIENTAUTH: 'clientAuth',
    EKU_CODESIGNING: 'codeSigning',
    EKU_EMAILPROTECTION: 'emailProtection',
    EKU_TIMESTAMPING: 'timeStamping',
    EKU_OCSPSIGNING: 'OCSPSigning',
    EKU_IPSECIKE: 'ipsecIKE',
    EKU_MSCODEIND: 'msCodeInd',
    EKU_MSCODECOM: 'msCodeCom',
    EKU_MSCTLSIGN: 'msCTLSign',
    EKU_MSEFS: 'msEFS'
}

# Revocation reasons

REV_UNSPECIFIED = 1
REV_KEYCOMPROMISE = 2
REV_CACOMPROMISE = 3
REV_AFFILIATIONCHANGED = 4
REV_SUPERSEDED = 5
REV_CESSATIONOFOPERATION = 6
REV_CERTIFICATEHOLD = 7

# All revocation reasons
REV_REASON = {
    REV_UNSPECIFIED: 'unspecified',
    REV_KEYCOMPROMISE: 'keyCompromise',
    REV_CACOMPROMISE: 'CACompromise',
    REV_AFFILIATIONCHANGED: 'affiliationChanged',
    REV_SUPERSEDED: 'superseded',
    REV_CESSATIONOFOPERATION: 'cessationOfOperation',
    REV_CERTIFICATEHOLD: 'certificateHold',
}

# User selectable reasons
REV_USER = {
    REV_UNSPECIFIED: 'Unspecified',
    REV_KEYCOMPROMISE: 'Key Compromise',
    REV_AFFILIATIONCHANGED: 'Affiliation Changed',
    REV_SUPERSEDED: 'Superseded',
    REV_CESSATIONOFOPERATION: 'Cessation of Operation',
}

KEY_RSA = 1
KEY_DSA = 2
KEY_EC = 3

KEY_TYPE = {
    KEY_RSA: 'RSA',
    KEY_DSA: 'DSA',
    KEY_EC: 'EC',
}

# Possible keyUsage combinations depending on the algorithm used by
# a public key
KEY_TYPE_KEY_USAGE_EE = {
    KEY_RSA: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
        KU_KEYENCIPHERMENT,
        KU_DATAENCIPHERMENT,
    ],
    KEY_DSA: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
    ],
    # TODO: There really are two different EC public keys
    # depending on the algorithm in SubjectPublicKeyInfo
    # id-ecPublicKey and id-ecDH or id-ecMQV
    KEY_EC: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
        KU_KEYAGREEMENT,
        KU_ENCIPHERONLY,
        KU_DECIPHERONLY,
    ],
}

KEY_TYPE_KEY_USAGE_CA = {
    KEY_RSA: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
        KU_KEYENCIPHERMENT,
        KU_DATAENCIPHERMENT,
        KU_KEYCERTSIGN,
        KU_CRLSIGN,
    ],
    KEY_DSA: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
        KU_KEYCERTSIGN,
        KU_CRLSIGN,
    ],
    # TODO: There really are two different EC public keys
    # depending on the algorithm in SubjectPublicKeyInfo
    # id-ecPublicKey and id-ecDH or id-ecMQV
    KEY_EC: [
        KU_DIGITALSIGNATURE,
        KU_NONREPUDIATION,
        KU_KEYAGREEMENT,
        KU_ENCIPHERONLY,
        KU_DECIPHERONLY,
        KU_KEYCERTSIGN,
        KU_CRLSIGN,
    ],
}
