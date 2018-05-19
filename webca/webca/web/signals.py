"""
Model signals.
"""

from django.contrib.auth.models import User
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from webca.web.models import CAUser


@receiver(post_save, sender=User)
def save_ca_user(sender, instance, **kwargs):
    """Save the instance of CAUser."""
    try:
        instance.ca_user
    except CAUser.DoesNotExist:
        CAUser.objects.create(user=instance)
    instance.ca_user.save()
