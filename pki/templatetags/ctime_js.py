from django import template
import time

register = template.Library()

@register.simple_tag
def ctime_js():
    return time.time()*1000
