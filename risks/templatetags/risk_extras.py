from django import template
register = template.Library()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

@register.filter
def risk_color(rating):
    return {
        "Critical": "danger",
        "Severe": "warning",
        "Moderate": "warning",
        "Sustainable": "success",
    }.get(rating, "secondary")

@register.filter
def level_label(value):
    if value == "Medium":
        return "Moderate"
    return value
