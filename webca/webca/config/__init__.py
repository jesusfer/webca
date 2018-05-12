"""
Django app to store generic configuration settings.
"""

def new_crl_config():
    """Build a new CRL configuration dictionary."""
    return dict(
        path='',
        last_update='',
        next_update='',
        days=15,
        delta_last_update='',
        delta_next_update='',
        delta_days=1,
        sequence=1,
        status='',
    )
