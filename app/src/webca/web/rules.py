"""
Permission rules for this app.

Rules: https://github.com/dfunckt/django-rules
"""
import rules

# Permission names
PERM_USE_TEMPLATE = 'web.use_template'

# Predicates
@rules.Predicate
def use_template(user, template):
    """Check if the user is member of a group allowed to use the template."""
    user_groups = user.groups.all()
    allowed = template.allowed_groups.all()
    for group in allowed:
        if group in user_groups:
            return True
    return False

# Rules
rules.add_perm(PERM_USE_TEMPLATE, use_template)
