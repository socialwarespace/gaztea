from django.contrib import admin
from gazteaApp.models import Herriak


class AuthorAdmin(admin.ModelAdmin):
    pass
admin.site.register(Herriak)
