"""
Custom model fields for web.
"""
from django.core.exceptions import ValidationError

from webca.crypto import constants
from webca.utils.fields import MultiSelectField

SAN_NONE = 'None'
SAN_ALLOWED = [
    (SAN_NONE, 'None'),
    ('DNS', 'DNS'),
    ('IP', 'IP'),
    ('URI', 'URI'),
    ('email', 'E-Mail'),
    ('UTF8', 'UTF8 String'),
]


class SubjectAltNameField(MultiSelectField):
    """Subject Alternative Name model field."""

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 250
        kwargs['choices'] = SAN_ALLOWED
        kwargs['default'] = SAN_NONE
        super().__init__(*args, **kwargs)

    def validate(self, value, model_instance):
        """
        None and anything else cannot be chosen at the same time.
        """
        super().validate(value, model_instance)
        is_none = SAN_NONE in value
        if is_none and len(value) > 1:
            raise ValidationError(
                'If option "None" is selected, nothing else can be selected',
                code='invalid-san-options',
                params={}
            )
        return


class KeyUsageField(MultiSelectField):
    """
    Key Usage field.

    Bits in the KeyUsage type are used as follows:

        The digitalSignature bit is asserted when the subject public key
        is used for verifying digital signatures, other than signatures on
        certificates (bit 5) and CRLs (bit 6), such as those used in an
        entity authentication service, a data origin authentication
        service, and/or an integrity service.

        The nonRepudiation bit is asserted when the subject public key is
        used to verify digital signatures, other than signatures on
        certificates (bit 5) and CRLs (bit 6), used to provide a non-
        repudiation service that protects against the signing entity
        falsely denying some action.  In the case of later conflict, a
        reliable third party may determine the authenticity of the signed
        data.  (Note that recent editions of X.509 have renamed the
        nonRepudiation bit to contentCommitment.)

        The keyEncipherment bit is asserted when the subject public key is
        used for enciphering private or secret keys, i.e., for key
        transport.  For example, this bit shall be set when an RSA public
        key is to be used for encrypting a symmetric content-decryption
        key or an asymmetric private key.

        The dataEncipherment bit is asserted when the subject public key
        is used for directly enciphering raw user data without the use of
        an intermediate symmetric cipher.  Note that the use of this bit
        is extremely uncommon; almost all applications use key transport
        or key agreement to establish a symmetric key.

        The keyAgreement bit is asserted when the subject public key is
        used for key agreement.  For example, when a Diffie-Hellman key is
        to be used for key management, then this bit is set.

        The keyCertSign bit is asserted when the subject public key is
        used for verifying signatures on public key certificates.  If the
        keyCertSign bit is asserted, then the cA bit in the basic
        constraints extension (Section 4.2.1.9) MUST also be asserted.

        The cRLSign bit is asserted when the subject public key is used
        for verifying signatures on certificate revocation lists (e.g.,
        CRLs, delta CRLs, or ARLs).

        The meaning of the encipherOnly bit is undefined in the absence of
        the keyAgreement bit.  When the encipherOnly bit is asserted and
        the keyAgreement bit is also set, the subject public key may be
        used only for enciphering data while performing key agreement.

        The meaning of the decipherOnly bit is undefined in the absence of
        the keyAgreement bit.  When the decipherOnly bit is asserted and
        the keyAgreement bit is also set, the subject public key may be
        used only for deciphering data while performing key agreement.

    If the keyUsage extension is present, then the subject public key
    MUST NOT be used to verify signatures on certificates or CRLs unless
    the corresponding keyCertSign or cRLSign bit is set.  If the subject
    public key is only to be used for verifying signatures on
    certificates and/or CRLs, then the digitalSignature and
    nonRepudiation bits SHOULD NOT be set.  However, the digitalSignature
    and/or nonRepudiation bits MAY be set in addition to the keyCertSign
    and/or cRLSign bits if the subject public key is to be used to verify
    signatures on certificates and/or CRLs as well as other objects.

    Combining the nonRepudiation bit in the keyUsage certificate
    extension with other keyUsage bits may have security implications
    depending on the context in which the certificate is to be used.
    Further distinctions between the digitalSignature and nonRepudiation
    bits may be provided in specific certificate policies.
    """

    def __init__(self, *args, **kwargs):
        choices = [(x, x) for x in constants.KEY_USAGE.values()]
        kwargs['max_length'] = 250
        kwargs['choices'] = choices
        kwargs['default'] = constants.KEY_USAGE[constants.KU_DIGITALSIGNATURE]
        super().__init__(*args, **kwargs)

    def validate(self, value, model_instance):
        """
        encipherOnly and decipherOnly can only be chosen if keyAgreement is chosen

        Extended validation could be done regarding the other fields of the model.
        """
        super().validate(value, model_instance)
        for usage in value:
            if usage not in constants.KEY_USAGE.values():
                raise ValidationError(
                    'Selected usage is not valid: %(usage)s',
                    code='invalid-usage',
                    params={'usage': usage}
                )
        is_encipher = constants.KEY_USAGE[constants.KU_ENCIPHERONLY] in value
        is_decipher = constants.KEY_USAGE[constants.KU_DECIPHERONLY] in value
        if constants.KEY_USAGE[constants.KU_KEYAGREEMENT] in value:
            if is_encipher and is_decipher:
                raise ValidationError(
                    'encipherOnly and decipherOnly cannot be set at the same time',
                    code='invalid-keyagreement',
                )
        else:
            if is_encipher or is_decipher:
                raise ValidationError(
                    'encipherOnly or decipherOnly must be set with keyAgreement',
                    code='invalid-keyagreement',
                )

class ExtendedKeyUsageField(MultiSelectField):
    """
    Extended Key Usage Field.
    """
    def __init__(self, *args, **kwargs):
        choices = [(x, x) for x in constants.EXT_KEY_USAGE.values()]
        kwargs['max_length'] = 250
        kwargs['choices'] = choices
        super().__init__(*args, **kwargs)
