"""
Utils that will be used anywhere in the project.
"""
import re
from webca.crypto.utils import name_to_components

def dict_as_tuples(dct):
    """Transforms a dict to a choices list of tuples."""
    lst = []
    for key in dct.keys():
        lst.append((key, dct[key]))
    return lst


def tuples_as_dict(tuples):
    """Transforms a list of tuples into a dict."""
    dct = {}
    tuples = [x for x in tuples if len(x) == 2]
    for first, second in tuples:
        dct[first] = second
    return dct


def subject_display(subject):
    """Display a subject nicely.

    Arguments
    ---------
    `subject` str : OpenSSL subject.
    """
    name = tuples_as_dict(name_to_components(subject))
    print(name)
    output = ""
    for part in ['CN', 'O', 'OU', 'C', 'ST', 'L']:
        if part in name:
            if not output:
                output = '{}={}'.format(part, name[part])
            else:
                output += ', {}={}'.format(part, name[part])
    return output
