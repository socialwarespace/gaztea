
from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.detail, name='index'),
    url(r'^ajax/validate_herriak/$', views.validate_herriak, name='validate_herriak'),

]
