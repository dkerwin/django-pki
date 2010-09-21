from django import template

register = template.Library()

@register.filter(name='model_for_object')
def model_for_object(obj):
    return obj.__class__.__name__
