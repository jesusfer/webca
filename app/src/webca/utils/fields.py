"""
Custom model fields for the project.
"""
from django import forms
from django.contrib.humanize.templatetags.humanize import apnumber
from django.core.exceptions import ValidationError
from django.db import models
from django.template.defaultfilters import pluralize
from django.utils.text import capfirst


class MultiSelectFormField(forms.MultipleChoiceField):
    """Multi select checkbox form field with max_choices option."""
    widget = forms.CheckboxSelectMultiple

    def __init__(self, *args, **kwargs):
        self.max_choices = kwargs.pop('max_choices', 0)
        super(MultiSelectFormField, self).__init__(*args, **kwargs)

    def clean(self, value):
        if not value and self.required:
            raise forms.ValidationError(self.error_messages['required'])
        if value and self.max_choices and len(value) > self.max_choices:
            raise forms.ValidationError(
                'You must select a maximum of %s choice%s.'
                % (
                    apnumber(self.max_choices),
                    pluralize(self.max_choices)))
        return value


class MultiSelectField(models.CharField):
    """
    Multiselection field that stores choices in a comma separated list.
    """
    # __metaclass__ = models.SubfieldBase

    description = "Multiselection field."

    def __init__(self, *args, **kwargs):
        self.max_choices = kwargs.pop('max_choices', 0)
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        """Deconstruct for serializers.

        For any configuration of your Field instance,
        deconstruct() must return arguments that you can pass to __init__
        to reconstruct that state.
        """
        name, path, args, kwargs = super().deconstruct()
        return name, path, args, kwargs

    def to_python(self, value):
        """
        to_python() is called by deserialization and during the clean()
        method used from forms.
        """
        if isinstance(value, list):
            return value
        if value is None:
            return value
        return value.split(',')

    def from_db_value(self, value, expression, connection):
        """
        from_db_value() will be called in all circumstances when the data is loaded
        from the database, including in aggregates and values() calls.
        """
        if value is None:
            return value
        return value.split(',')

    def get_prep_value(self, value):
        """
        Override get_prep_value() to convert Python objects back to query values.
        """
        if isinstance(value, str):
            return value
        elif isinstance(value, list):
            return ",".join(value)
        return None

    def formfield(self, **kwargs):
        """
        Returns the default django.forms.Field of this field for ModelForm.
        """
        # don't call super, as that overrides default widget if it has choices
        defaults = {
            # 'required': not self.blank,
            'required': not self.blank,
            'label': capfirst(self.verbose_name),
            'help_text': self.help_text,
            'choices': self.choices,
            'max_choices': self.max_choices,
        }
        if self.has_default():
            defaults['initial'] = self.get_default()
        defaults.update(kwargs)
        return MultiSelectFormField(**defaults)

    def get_internal_type(self):
        return "CharField"

    def value_to_string(self, obj):
        value = self.value_from_object(obj)
        return self.get_prep_value(value)

    def validate(self, value, model_instance):
        # All possible choices
        arr_choices = self.get_choices_selected(self.get_choices_default())
        for opt_select in value:
            if opt_select not in arr_choices:
                raise ValidationError(
                    self.error_messages['invalid_choice'] % value)
        return

    def get_choices_default(self):
        """Get the choices for this field."""
        return self.get_choices(include_blank=False)

    def get_choices_selected(self, arr_choices=''):
        """Get the values of the choices."""
        if not arr_choices:
            return False
        selected = []
        for choice_selected in arr_choices:
            selected.append(choice_selected[0])
        return selected


"""
    def get_FIELD_display(self, field):
        value = getattr(self, field.attname)
        choicedict = dict(field.choices)

    def contribute_to_class(self, cls, name):
        super(MultiSelectField, self).contribute_to_class(cls, name)
        if self.choices:
            func = lambda self, fieldname = name, choicedict = dict(self.choices): ",".join(
                [choicedict.get(value, value) for value in getattr(self, fieldname)])
            setattr(cls, 'get_%s_display' % self.name, func)

"""
