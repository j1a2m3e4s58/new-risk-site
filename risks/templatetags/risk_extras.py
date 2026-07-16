from django import template
register = template.Library()


def normalize_risk_label(value):
    value = (value or "").strip()
    if value in ["Very High", "High", "Critical"]:
        return "High"
    if value in ["Medium", "Moderate", "Severe"]:
        return "Medium"
    return "Low"


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def risk_color(rating):
    return {
        "High": "danger",
        "Medium": "warning",
        "Low": "success",
    }.get(normalize_risk_label(rating), "secondary")


@register.filter
def level_label(value):
    return normalize_risk_label(value)
