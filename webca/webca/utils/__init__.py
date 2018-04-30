"""
Utils that will be used anywhere in the project.
"""
import re

def dict_as_tuples(dct):
    """Transforms a dict to a choices list of tuples."""
    lst = []
    for key in dct.keys():
        lst.append((key, dct[key]))
    return lst

def subject_display(subject):
    """Display a subject nicely."""
    if 'CN=' in subject:
        return re.search('CN=([^/]+)', subject).groups()[0]
    if 'emailAddress=' in subject:
        return re.search('emailAddress=([^/]+)', subject).groups()[0]
    return subject
