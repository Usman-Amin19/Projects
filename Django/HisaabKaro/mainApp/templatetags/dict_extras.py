from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """
    Custom template filter to get an item from a dictionary using a variable key.
    Usage: {{ mydict|get_item:variable_key }}
    """
    try:
        return dictionary.get(str(key))
    except (AttributeError, KeyError):
        return None
