"""
Utils that will be used anywhere in the project.
"""
def dict_as_tuples(dct):
    """Transforms a dict to a choices list of tuples."""
    lst = []
    for key in dct.keys():
        lst.append((key, dct[key]))
    return lst
