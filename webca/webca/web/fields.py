"""
Custom model fields for web.
"""
from django.core.exceptions import ValidationError

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
